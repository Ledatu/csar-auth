// Package sts implements the Security Token Service for service-to-service
// authentication. Service accounts exchange short-lived signed JWT assertions
// for scoped access tokens, following the jwt-bearer grant type (RFC 7523).
package sts

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Ledatu/csar-authn/internal/config"
	"github.com/Ledatu/csar-authn/internal/session"
)

const clockSkew = 30 * time.Second

// serviceAccount holds a loaded service account's public key and permissions.
type serviceAccount struct {
	PublicKey         crypto.PublicKey
	Algorithm         string          // detected from key type: "RS256" or "EdDSA"
	AllowedAudiences  map[string]bool // set of allowed audience strings
	AllowAllAudiences bool            // when true, omitting audience param returns all allowed
	TokenTTL          time.Duration   // 0 means use default
}

// Handler handles STS token exchange requests (POST /sts/token).
type Handler struct {
	accounts        map[string]*serviceAccount // keyed by SA name
	sessionMgr      *session.Manager
	replayStore     ReplayStore
	assertionMaxAge time.Duration
	defaultTTL      time.Duration // from jwt.ttl
	issuer          string        // expected "aud" in incoming assertions
	logger          *slog.Logger
}

// New creates an STS handler, loading all service account public keys.
// If replayStore is nil, a local in-memory replay store is used as fallback.
// Returns an error if any key fails to load (fail-fast).
func New(stsCfg config.STSConfig, jwtCfg config.JWTConfig, sessionMgr *session.Manager, replayStore ReplayStore, logger *slog.Logger) (*Handler, error) {
	accounts := make(map[string]*serviceAccount, len(stsCfg.ServiceAccounts))

	for name, saCfg := range stsCfg.ServiceAccounts {
		pubKey, err := loadPublicKey(saCfg)
		if err != nil {
			return nil, fmt.Errorf("loading public key for SA %q: %w", name, err)
		}

		alg, err := detectAlgorithm(pubKey)
		if err != nil {
			return nil, fmt.Errorf("SA %q: %w", name, err)
		}

		audSet := make(map[string]bool, len(saCfg.AllowedAudiences))
		for _, a := range saCfg.AllowedAudiences {
			audSet[a] = true
		}

		accounts[name] = &serviceAccount{
			PublicKey:         pubKey,
			Algorithm:         alg,
			AllowedAudiences:  audSet,
			AllowAllAudiences: saCfg.AllowAllAudiences,
			TokenTTL:          saCfg.TokenTTL.Std(),
		}
		logger.Info("loaded STS service account",
			"name", name,
			"algorithm", alg,
			"audiences", saCfg.AllowedAudiences,
		)
	}

	if replayStore == nil {
		replayStore = NewMemoryReplayStore()
		logger.Warn("STS using in-memory replay store; not suitable for multi-instance production")
	}

	return &Handler{
		accounts:        accounts,
		sessionMgr:      sessionMgr,
		replayStore:     replayStore,
		assertionMaxAge: stsCfg.AssertionMaxAge.Std(),
		defaultTTL:      jwtCfg.TTL.Std(),
		issuer:          jwtCfg.Issuer,
		logger:          logger,
	}, nil
}

// ServeHTTP handles POST /sts/token requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	grantType := r.FormValue("grant_type")
	assertion := r.FormValue("assertion")
	audience := r.FormValue("audience")

	// Validate grant type.
	if grantType != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be urn:ietf:params:oauth:grant-type:jwt-bearer")
		return
	}

	if assertion == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "assertion is required")
		return
	}

	// Pre-parse assertion to extract issuer (SA name) before full verification.
	issuer, err := extractIssuer(assertion)
	if err != nil {
		h.logger.Warn("assertion parse failed", "error", err)
		writeError(w, http.StatusBadRequest, "invalid_grant", "invalid assertion")
		return
	}

	// Look up the service account.
	sa, ok := h.accounts[issuer]
	if !ok {
		h.logger.Warn("unknown service account", "sa", issuer)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "authentication failed")
		return
	}

	// Parse and verify the full assertion.
	claims, err := parseAndVerifyAssertion(assertion, sa, h.issuer)
	if err != nil {
		h.logger.Warn("assertion verification failed", "sa", issuer, "error", err)
		writeError(w, http.StatusUnauthorized, "invalid_grant", "authentication failed")
		return
	}

	// Require iat and enforce assertion lifetime bounds.
	if claims.Iat == 0 {
		writeError(w, http.StatusBadRequest, "invalid_grant", "iat claim is required")
		return
	}
	iatTime := time.Unix(claims.Iat, 0)
	if iatTime.After(time.Now().Add(clockSkew)) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "assertion issued in the future")
		return
	}
	assertionAge := time.Since(iatTime)
	if assertionAge > h.assertionMaxAge+clockSkew {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "assertion too old")
		return
	}
	lifetime := time.Duration(claims.Exp-claims.Iat) * time.Second
	if lifetime <= 0 || lifetime > h.assertionMaxAge {
		writeError(w, http.StatusBadRequest, "invalid_grant", "assertion lifetime out of bounds")
		return
	}
	maxExp := time.Now().Add(h.assertionMaxAge + clockSkew)
	if time.Unix(claims.Exp, 0).After(maxExp) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "assertion exp too far in the future")
		return
	}

	// Require JTI for replay protection.
	if claims.Jti == "" {
		writeError(w, http.StatusBadRequest, "invalid_grant", "jti claim is required")
		return
	}

	replayed, err := h.replayStore.CheckAndRecord(r.Context(), claims.Iss, claims.Jti, time.Unix(claims.Exp, 0))
	if err != nil {
		h.logger.Error("replay store check failed", "sa", issuer, "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "replay check failed")
		return
	}
	if replayed {
		writeError(w, http.StatusUnauthorized, "invalid_grant", "assertion already used")
		return
	}

	// Resolve audiences.
	var audiences []string
	if audience != "" {
		// Validate requested audience against SA's allowed audiences.
		if !sa.AllowedAudiences[audience] {
			writeError(w, http.StatusForbidden, "access_denied", "audience not allowed")
			return
		}
		audiences = []string{audience}
	} else if sa.AllowAllAudiences {
		// SA explicitly opts in to receiving all allowed audiences when none requested.
		audiences = make([]string, 0, len(sa.AllowedAudiences))
		for a := range sa.AllowedAudiences {
			audiences = append(audiences, a)
		}
	} else {
		writeError(w, http.StatusBadRequest, "invalid_request", "audience parameter is required")
		return
	}

	// Determine TTL: SA-specific or global default.
	ttl := h.defaultTTL
	if sa.TokenTTL > 0 {
		ttl = sa.TokenTTL
	}

	// Issue the scoped access token.
	token, err := h.sessionMgr.IssueScopedToken(issuer, audiences, ttl)
	if err != nil {
		h.logger.Error("failed to issue STS token", "sa", issuer, "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	h.logger.Info("STS token issued",
		"sa", issuer,
		"audiences", audiences,
		"ttl", ttl.String(),
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
	})
}

// ---------------------------------------------------------------------------
// Public key loading
// ---------------------------------------------------------------------------

// loadPublicKey reads a PEM-encoded PKIX public key from file or inline config.
func loadPublicKey(saCfg config.ServiceAccountConfig) (crypto.PublicKey, error) {
	var pemData []byte

	if saCfg.PublicKeyFile != "" {
		data, err := os.ReadFile(saCfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", saCfg.PublicKeyFile, err)
		}
		pemData = data
	} else {
		pemData = []byte(saCfg.PublicKey)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return pub, nil
}

// detectAlgorithm returns the JWT algorithm name for the given public key type.
func detectAlgorithm(pub crypto.PublicKey) (string, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RS256", nil
	case ed25519.PublicKey:
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// ---------------------------------------------------------------------------
// JWT assertion parsing and verification
// ---------------------------------------------------------------------------

// assertionHeader represents the JWT header of an incoming assertion.
type assertionHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// assertionClaims represents the JWT payload of an incoming assertion.
type assertionClaims struct {
	Iss string `json:"iss"` // service account name
	Aud string `json:"aud"` // must match csar-authn's issuer
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"` // unique ID for replay prevention
}

// extractIssuer pre-parses a JWT payload to get the "iss" claim without verification.
func extractIssuer(tokenStr string) (string, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("parsing claims: %w", err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("iss claim is required")
	}
	return c.Iss, nil
}

// parseAndVerifyAssertion fully parses, verifies the signature, and validates
// claims of an incoming JWT assertion.
func parseAndVerifyAssertion(tokenStr string, sa *serviceAccount, expectedAud string) (*assertionClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode and validate header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var header assertionHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}
	if header.Alg != sa.Algorithm {
		return nil, fmt.Errorf("algorithm mismatch: header %q, expected %q", header.Alg, sa.Algorithm)
	}

	// Decode payload.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	var claims assertionClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	// Verify signature.
	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if err := verifySignature(signingInput, sigBytes, sa.PublicKey, sa.Algorithm); err != nil {
		return nil, fmt.Errorf("assertion signature invalid: %w", err)
	}

	// Validate time-based claims.
	now := time.Now()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(clockSkew)) {
		return nil, fmt.Errorf("assertion expired")
	}
	if claims.Nbf != 0 && now.Before(time.Unix(claims.Nbf, 0).Add(-clockSkew)) {
		return nil, fmt.Errorf("assertion not yet valid (nbf)")
	}

	// Validate audience — must match csar-authn's own issuer.
	if claims.Aud != expectedAud {
		return nil, fmt.Errorf("audience mismatch: got %q, expected %q", claims.Aud, expectedAud)
	}

	return &claims, nil
}

// verifySignature verifies a JWT signature using the given public key and algorithm.
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

// ---------------------------------------------------------------------------
// HTTP response types
// ---------------------------------------------------------------------------

// tokenResponse is the successful STS token exchange response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"` // always "Bearer"
	ExpiresIn   int    `json:"expires_in"` // seconds
}

// errorResponse matches RFC 6749 section 5.2.
type errorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{
		Error:       errCode,
		Description: description,
	})
}
