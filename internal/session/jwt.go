package session

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Ledatu/csar-auth/internal/config"
)

// Claims represents the JWT payload issued by csar-auth.
type Claims struct {
	Sub         string `json:"sub"`                    // user UUID
	Email       string `json:"email,omitempty"`         // user email
	DisplayName string `json:"display_name,omitempty"`  // user display name
	Iss         string `json:"iss"`                     // issuer
	Aud         string `json:"aud"`                     // audience
	Exp         int64  `json:"exp"`                     // expiration (Unix)
	Iat         int64  `json:"iat"`                     // issued at (Unix)
	Nbf         int64  `json:"nbf"`                     // not before (Unix)
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
	claims := Claims{
		Sub:         userID,
		Email:       email,
		DisplayName: displayName,
		Iss:         m.cfg.Issuer,
		Aud:         m.cfg.Audience,
		Iat:         now.Unix(),
		Nbf:         now.Unix(),
		Exp:         now.Add(m.cfg.TTL.Std()).Unix(),
	}

	return m.signToken(claims)
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
	Iss string   `json:"iss"` // csar-auth issuer
	Aud []string `json:"aud"` // scoped audiences
	Exp int64    `json:"exp"` // expiration (Unix)
	Iat int64    `json:"iat"` // issued at (Unix)
	Nbf int64    `json:"nbf"` // not before (Unix)
}

// IssueScopedToken creates a signed JWT for an STS token exchange.
// The token contains an audience array (not a single string) for scope enforcement.
func (m *Manager) IssueScopedToken(sub string, audiences []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := STSClaims{
		Sub: sub,
		Iss: m.cfg.Issuer,
		Aud: audiences,
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Exp: now.Add(ttl).Unix(),
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	return m.signPayload(claimsJSON)
}

func (m *Manager) signToken(claims Claims) (string, error) {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling claims: %w", err)
	}
	return m.signPayload(claimsJSON)
}

// signPayload builds a JWT from pre-marshalled claims JSON.
func (m *Manager) signPayload(claimsJSON []byte) (string, error) {
	header := map[string]string{
		"alg": m.keys.Algorithm,
		"typ": "JWT",
		"kid": m.keys.KID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshalling header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	sig, err := sign([]byte(signingInput), m.keys.PrivateKey, m.keys.Algorithm)
	if err != nil {
		return "", err
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

func sign(data []byte, key crypto.Signer, alg string) ([]byte, error) {
	switch alg {
	case "RS256":
		h := crypto.SHA256.New()
		h.Write(data)
		return key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)

	case "EdDSA":
		// Ed25519 signs the raw message, not a hash.
		switch k := key.(type) {
		case ed25519.PrivateKey:
			return ed25519.Sign(k, data), nil
		default:
			return nil, fmt.Errorf("EdDSA requires ed25519.PrivateKey, got %T", key)
		}

	case "ES256":
		h := crypto.SHA256.New()
		h.Write(data)
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ES256 requires *ecdsa.PrivateKey, got %T", key)
		}
		return ecdsa.SignASN1(rand.Reader, ecKey, h.Sum(nil))

	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
}

const verifyClockSkew = 30 * time.Second

// VerifyToken fully parses, verifies the signature, and validates claims of a
// JWT issued by this Manager. Unlike a decode-only path, this ensures that
// forged or expired tokens are rejected.
func (m *Manager) VerifyToken(tokenStr string) (*Claims, error) {
	parts := splitJWT(tokenStr)
	if parts == nil {
		return nil, fmt.Errorf("malformed JWT: expected 3 dot-separated parts")
	}

	// Decode and validate header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}
	if header.Alg != m.keys.Algorithm {
		return nil, fmt.Errorf("algorithm mismatch: got %q, expected %q", header.Alg, m.keys.Algorithm)
	}
	if header.Kid != "" && header.Kid != m.keys.KID {
		return nil, fmt.Errorf("kid mismatch: got %q, expected %q", header.Kid, m.keys.KID)
	}

	// Verify signature.
	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if err := verifySignature(signingInput, sigBytes, m.keys.PublicKey, m.keys.Algorithm); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Decode and validate claims.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(verifyClockSkew)) {
		return nil, fmt.Errorf("token expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-verifyClockSkew)) {
		return nil, fmt.Errorf("token not yet valid (nbf)")
	}
	if claims.Iss != m.cfg.Issuer {
		return nil, fmt.Errorf("issuer mismatch: got %q, expected %q", claims.Iss, m.cfg.Issuer)
	}
	if claims.Aud != m.cfg.Audience {
		return nil, fmt.Errorf("audience mismatch: got %q, expected %q", claims.Aud, m.cfg.Audience)
	}

	return &claims, nil
}

func splitJWT(s string) []string {
	parts := [3]string{}
	for i := 0; i < 3; i++ {
		if i < 2 {
			idx := indexOf(s, '.')
			if idx < 0 {
				return nil
			}
			parts[i] = s[:idx]
			s = s[idx+1:]
		} else {
			if s == "" {
				return nil
			}
			parts[i] = s
		}
	}
	return parts[:]
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func verifySignature(signingInput, signature []byte, pub crypto.PublicKey, alg string) error {
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected RSA public key, got %T", pub)
		}
		h := crypto.SHA256.New()
		h.Write(signingInput)
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h.Sum(nil), signature)

	case "EdDSA":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected Ed25519 public key, got %T", pub)
		}
		if !ed25519.Verify(edPub, signingInput, signature) {
			return fmt.Errorf("Ed25519 signature invalid")
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// rsaSign signs with PKCS1v15 for RS256.
func rsaSign(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
}
