package session

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-core/jwtx"
)

// Claims represents the JWT payload issued by csar-authn.
type Claims struct {
	Sub         string `json:"sub"`                    // user UUID
	Email       string `json:"email,omitempty"`        // user email
	DisplayName string `json:"display_name,omitempty"` // user display name
	Iss         string `json:"iss"`                    // issuer
	Aud         string `json:"aud"`                    // audience
	Exp         int64  `json:"exp"`                    // expiration (Unix)
	Iat         int64  `json:"iat"`                    // issued at (Unix)
	Nbf         int64  `json:"nbf"`                    // not before (Unix)
}

// Manager handles JWT token signing.
type Manager struct {
	keys *KeyPair
	cfg  config.JWTConfig
}

// NewManager creates a session manager with the given key pair and config.
func NewManager(keys *KeyPair, cfg config.JWTConfig) *Manager {
	return &Manager{keys: keys, cfg: cfg}
}

// IssueToken creates a signed JWT for the given user.
func (m *Manager) IssueToken(userID, email, displayName string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID,
		"iss": m.cfg.Issuer,
		"aud": m.cfg.Audience,
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(m.cfg.TTL.Std())),
	}
	if email != "" {
		claims["email"] = email
	}
	if displayName != "" {
		claims["display_name"] = displayName
	}

	return jwtx.Sign(m.keys, claims)
}

// TTL returns the configured token lifetime.
func (m *Manager) TTL() time.Duration {
	return m.cfg.TTL.Std()
}

// Keys returns the key pair (for JWKS handler).
func (m *Manager) Keys() *KeyPair {
	return m.keys
}

// STSClaims represents the JWT payload for STS-issued scoped tokens.
type STSClaims struct {
	Sub string   `json:"sub"` // service account name
	Iss string   `json:"iss"` // csar-authn issuer
	Aud []string `json:"aud"` // scoped audiences
	Exp int64    `json:"exp"` // expiration (Unix)
	Iat int64    `json:"iat"` // issued at (Unix)
	Nbf int64    `json:"nbf"` // not before (Unix)
}

// IssueScopedToken creates a signed JWT for an STS token exchange.
func (m *Manager) IssueScopedToken(sub string, audiences []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": sub,
		"iss": m.cfg.Issuer,
		"aud": audiences,
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(ttl)),
	}
	return jwtx.Sign(m.keys, claims)
}

const verifyClockSkew = 30 * time.Second

// VerifyToken fully parses, verifies the signature, and validates claims of a
// JWT issued by this Manager.
func (m *Manager) VerifyToken(tokenStr string) (*Claims, error) {
	vt, err := jwtx.VerifyWithKey(tokenStr, m.keys.PublicKey, &jwtx.VerifyConfig{
		AllowedAlgorithms: []string{m.keys.Algorithm},
		RequiredIssuer:    m.cfg.Issuer,
		RequiredAudience:  m.cfg.Audience,
		ClockSkew:         verifyClockSkew,
	})
	if err != nil {
		return nil, err
	}

	// Re-parse claims into the typed struct for backward compatibility.
	claimBytes, err := json.Marshal(vt.Claims)
	if err != nil {
		return nil, fmt.Errorf("re-marshalling claims: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	return &claims, nil
}
