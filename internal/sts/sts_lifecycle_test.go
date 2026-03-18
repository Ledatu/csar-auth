package sts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func generateEdDSAKeyPEM(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return pub, priv, string(pemBytes)
}

func setupLifecycleEnv(t *testing.T) (*Handler, *mock.Store, ed25519.PrivateKey) {
	t.Helper()

	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(authPub)

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
		TTL:      config.NewDuration(time.Hour),
	}
	mgr := session.NewManager(kp, jwtCfg)

	_, saPriv, saPEM := generateEdDSAKeyPEM(t)
	st := mock.New()

	sa := &store.ServiceAccount{
		Name:              "lifecycle-sa",
		PublicKeyPEM:      saPEM,
		AllowedAudiences:  []string{"aud-a"},
		AllowAllAudiences: false,
		TokenTTL:          15 * time.Minute,
		Status:            "active",
	}
	if err := st.CreateServiceAccount(context.Background(), sa); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	h, err := New(
		ctx, st,
		5*time.Minute,
		time.Hour,
		testIssuer,
		mgr,
		NewMemoryReplayStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}

	return h, st, saPriv
}

func TestLifecycle_DBBackedSAWorks(t *testing.T) {
	h, _, saPriv := setupLifecycleEnv(t)

	c := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-1",
	}
	token := signJWT(t, saPriv, "EdDSA", c)
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {token},
		"audience":   {"aud-a"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLifecycle_RotateKeyRejectsOld(t *testing.T) {
	h, st, oldPriv := setupLifecycleEnv(t)

	_, newPriv, newPEM := generateEdDSAKeyPEM(t)

	if err := st.UpdateServiceAccountKey(context.Background(), "lifecycle-sa", newPEM); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Old key should be rejected.
	oldClaims := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-old",
	}
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, oldPriv, "EdDSA", oldClaims)},
		"audience":   {"aud-a"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("old key: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// New key should work.
	newClaims := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-new",
	}
	w = doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, newPriv, "EdDSA", newClaims)},
		"audience":   {"aud-a"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("new key: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLifecycle_RevokeRejectsExchange(t *testing.T) {
	h, st, saPriv := setupLifecycleEnv(t)

	if err := st.RevokeServiceAccount(context.Background(), "lifecycle-sa"); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}

	c := assertionClaims{
		Iss: "lifecycle-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-revoked",
	}
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, saPriv, "EdDSA", c)},
		"audience":   {"aud-a"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked SA: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLifecycle_ReloadPicksUpNewSA(t *testing.T) {
	h, st, _ := setupLifecycleEnv(t)

	_, newPriv, newPEM := generateEdDSAKeyPEM(t)
	newSA := &store.ServiceAccount{
		Name:              "new-sa",
		PublicKeyPEM:      newPEM,
		AllowedAudiences:  []string{"aud-x"},
		AllowAllAudiences: false,
		TokenTTL:          10 * time.Minute,
		Status:            "active",
	}
	if err := st.CreateServiceAccount(context.Background(), newSA); err != nil {
		t.Fatal(err)
	}

	// Before reload, new-sa should be unknown.
	c := assertionClaims{
		Iss: "new-sa",
		Aud: testIssuer,
		Exp: time.Now().Add(3 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Jti: "lc-new-sa-before",
	}
	w := doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, newPriv, "EdDSA", c)},
		"audience":   {"aud-x"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("before reload: expected 401, got %d", w.Code)
	}

	// After reload, new-sa should work.
	if err := h.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Jti = "lc-new-sa-after"
	w = doSTSRequest(t, h, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {signJWT(t, newPriv, "EdDSA", c)},
		"audience":   {"aud-x"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("after reload: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
