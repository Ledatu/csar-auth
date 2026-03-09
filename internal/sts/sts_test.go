package sts

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ledatu/csar-auth/internal/config"
	"github.com/Ledatu/csar-auth/internal/session"
)

var jtiCounter atomic.Int64

const testIssuer = "http://test-csar-auth"

type testEnv struct {
	handler   *Handler
	saPrivKey ed25519.PrivateKey
	saPubKey  ed25519.PublicKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	saPub, saPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating SA key: %v", err)
	}

	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating auth key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(authPub)
	if err != nil {
		t.Fatalf("marshalling auth public key: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(authPriv)
	if err != nil {
		t.Fatalf("marshalling auth private key: %v", err)
	}
	_ = privBytes

	kp := &session.KeyPair{
		PrivateKey: authPriv,
		PublicKey:  authPub,
		Algorithm:  "EdDSA",
		KID:        "test-kid",
		PublicDER:  pubDER,
	}

	jwtCfg := config.JWTConfig{
		Issuer:   testIssuer,
		Audience: "test-audience",
		TTL:      config.Duration(time.Hour),
	}
	mgr := session.NewManager(kp, jwtCfg)

	h := &Handler{
		accounts: map[string]*serviceAccount{
			"test-sa": {
				PublicKey:         saPub,
				Algorithm:         "EdDSA",
				AllowedAudiences:  map[string]bool{"aud-a": true, "aud-b": true},
				AllowAllAudiences: false,
				TokenTTL:          30 * time.Minute,
			},
		},
		sessionMgr:      mgr,
		replayStore:     NewMemoryReplayStore(),
		assertionMaxAge: 5 * time.Minute,
		defaultTTL:      time.Hour,
		issuer:          testIssuer,
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	return &testEnv{handler: h, saPrivKey: saPriv, saPubKey: saPub}
}

func (te *testEnv) signAssertion(t *testing.T, claims assertionClaims) string {
	t.Helper()
	return signJWT(t, te.saPrivKey, "EdDSA", claims)
}

func signJWT(t *testing.T, key crypto.Signer, alg string, payload any) string {
	t.Helper()

	header, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(payload)

	h64 := base64.RawURLEncoding.EncodeToString(header)
	b64 := base64.RawURLEncoding.EncodeToString(body)
	signingInput := h64 + "." + b64

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519 key")
	}
	sig := ed25519.Sign(edKey, []byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func doSTSRequest(t *testing.T, handler http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := form.Encode()
	req := httptest.NewRequest(http.MethodPost, "/sts/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func validClaims() assertionClaims {
	now := time.Now()
	return assertionClaims{
		Iss: "test-sa",
		Aud: testIssuer,
		Exp: now.Add(3 * time.Minute).Unix(),
		Iat: now.Unix(),
		Nbf: now.Unix(),
		Jti: fmt.Sprintf("jti-%d", jtiCounter.Add(1)),
	}
}

func TestSTS(t *testing.T) {
	tests := []struct {
		name       string
		form       func(te *testEnv) url.Values
		wantStatus int
		wantError  string
	}{
		{
			name: "happy path with explicit audience",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "missing audience fails closed by default",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name: "invalid grant type",
			form: func(te *testEnv) url.Values {
				return url.Values{
					"grant_type": {"authorization_code"},
					"assertion":  {"dummy"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "unsupported_grant_type",
		},
		{
			name: "missing assertion",
			form: func(te *testEnv) url.Values {
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name: "unknown service account",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Iss = "unknown-sa"
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
				}
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_grant",
		},
		{
			name: "invalid signature",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				token := te.signAssertion(t, c)
				// Corrupt the signature by replacing last few chars.
				token = token[:len(token)-4] + "XXXX"
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {token},
				}
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_grant",
		},
		{
			name: "expired assertion",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Exp = time.Now().Add(-10 * time.Minute).Unix()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
				}
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_grant",
		},
		{
			name: "audience not allowed",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"not-allowed"},
				}
			},
			wantStatus: http.StatusForbidden,
			wantError:  "access_denied",
		},
		{
			name: "jti replay detection",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Jti = "unique-jti-replay-test"
				assertion := te.signAssertion(t, c)
				// First request should succeed.
				first := doSTSRequest(t, te.handler, url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {assertion},
					"audience":   {"aud-a"},
				})
				if first.Code != http.StatusOK {
					t.Fatalf("first JTI request failed: %d %s", first.Code, first.Body.String())
				}
				// Second request with same JTI.
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {assertion},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_grant",
		},
		{
			name: "assertion too old",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Iat = time.Now().Add(-10 * time.Minute).Unix()
				c.Exp = time.Now().Add(-7 * time.Minute).Unix()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_grant",
		},
		{
			name: "assertion audience mismatch",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Aud = "http://wrong-issuer"
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_grant",
		},
		{
			name: "missing jti rejected",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Jti = ""
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name: "missing iat rejected",
			form: func(te *testEnv) url.Values {
				c := validClaims()
				c.Iat = 0
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name: "assertion lifetime exceeds limit",
			form: func(te *testEnv) url.Values {
				now := time.Now()
				c := validClaims()
				c.Iat = now.Unix()
				c.Exp = now.Add(time.Hour).Unix()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
		{
			name: "assertion exp too far in the future",
			form: func(te *testEnv) url.Values {
				now := time.Now()
				c := validClaims()
				c.Iat = now.Add(-2 * time.Minute).Unix()
				c.Exp = now.Add(time.Hour).Unix()
				return url.Values{
					"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
					"assertion":  {te.signAssertion(t, c)},
					"audience":   {"aud-a"},
				}
			},
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			te := newTestEnv(t)
			form := tt.form(te)
			w := doSTSRequest(t, te.handler, form)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tt.wantStatus, w.Body.String())
			}

			if tt.wantError != "" {
				var errResp errorResponse
				if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("decoding error response: %v; body = %s", err, w.Body.String())
				}
				if errResp.Error != tt.wantError {
					t.Errorf("error = %q, want %q", errResp.Error, tt.wantError)
				}
			}

			if tt.wantStatus == http.StatusOK {
				var resp tokenResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decoding success response: %v; body = %s", err, w.Body.String())
				}
				if resp.AccessToken == "" {
					t.Error("access_token is empty")
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("token_type = %q, want Bearer", resp.TokenType)
				}
				if resp.ExpiresIn <= 0 {
					t.Errorf("expires_in = %d, want > 0", resp.ExpiresIn)
				}
			}
		})
	}
}

func TestSTSResponseHeaders(t *testing.T) {
	te := newTestEnv(t)
	c := validClaims()
	w := doSTSRequest(t, te.handler, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {te.signAssertion(t, c)},
		"audience":   {"aud-a"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestSTSIssuedTokenClaims(t *testing.T) {
	te := newTestEnv(t)
	c := validClaims()
	w := doSTSRequest(t, te.handler, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {te.signAssertion(t, c)},
		"audience":   {"aud-a"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
	}

	var resp tokenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// Decode issued token payload (without verification, just for claim inspection).
	parts := strings.SplitN(resp.AccessToken, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("issued token is not a valid JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding issued token payload: %v", err)
	}

	var stsClaims session.STSClaims
	if err := json.Unmarshal(payload, &stsClaims); err != nil {
		t.Fatalf("parsing issued token claims: %v", err)
	}

	if stsClaims.Sub != "test-sa" {
		t.Errorf("sub = %q, want test-sa", stsClaims.Sub)
	}
	if stsClaims.Iss != testIssuer {
		t.Errorf("iss = %q, want %q", stsClaims.Iss, testIssuer)
	}
	if len(stsClaims.Aud) != 1 || stsClaims.Aud[0] != "aud-a" {
		t.Errorf("aud = %v, want [aud-a]", stsClaims.Aud)
	}
	if stsClaims.Exp == 0 {
		t.Error("exp is zero")
	}
}

// encodePEM is a test helper for PEM encoding.
func encodePEM(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshalling public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestSTSAllowAllAudiences(t *testing.T) {
	te := newTestEnv(t)
	// Enable AllowAllAudiences on the test SA.
	te.handler.accounts["test-sa"].AllowAllAudiences = true

	c := validClaims()
	w := doSTSRequest(t, te.handler, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {te.signAssertion(t, c)},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp tokenResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	parts := strings.SplitN(resp.AccessToken, ".", 3)
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var stsClaims session.STSClaims
	json.Unmarshal(payload, &stsClaims)

	if len(stsClaims.Aud) != 2 {
		t.Errorf("expected 2 audiences, got %d: %v", len(stsClaims.Aud), stsClaims.Aud)
	}
}

func TestSTSOversizedBody(t *testing.T) {
	te := newTestEnv(t)
	bigBody := strings.Repeat("x", 32*1024)
	req := httptest.NewRequest(http.MethodPost, "/sts/token", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	te.handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestSTSGenericErrorNoEnumeration(t *testing.T) {
	te := newTestEnv(t)

	// Unknown service account.
	unknownClaims := validClaims()
	unknownClaims.Iss = "nonexistent-sa"
	wUnknown := doSTSRequest(t, te.handler, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {te.signAssertion(t, unknownClaims)},
		"audience":   {"aud-a"},
	})

	// Known SA but corrupted signature.
	goodClaims := validClaims()
	badSigToken := te.signAssertion(t, goodClaims)
	badSigToken = badSigToken[:len(badSigToken)-4] + "XXXX"
	wBadSig := doSTSRequest(t, te.handler, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {badSigToken},
		"audience":   {"aud-a"},
	})

	if wUnknown.Code != wBadSig.Code {
		t.Errorf("status codes differ: unknown=%d bad_sig=%d", wUnknown.Code, wBadSig.Code)
	}

	var errUnknown, errBadSig errorResponse
	json.Unmarshal(wUnknown.Body.Bytes(), &errUnknown)
	json.Unmarshal(wBadSig.Body.Bytes(), &errBadSig)

	if errUnknown.Error != errBadSig.Error {
		t.Errorf("error codes differ: unknown=%q bad_sig=%q", errUnknown.Error, errBadSig.Error)
	}
	if errUnknown.Description != errBadSig.Description {
		t.Errorf("error descriptions differ: unknown=%q bad_sig=%q; should be identical to prevent enumeration",
			errUnknown.Description, errBadSig.Description)
	}
}
