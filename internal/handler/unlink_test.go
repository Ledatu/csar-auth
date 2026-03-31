package handler

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
)

func TestUnlinkProvider_AuditRecorded(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	jwtCfg := config.JWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      authnconfig.NewDuration(time.Hour),
	}
	sm := session.NewManager(kp, jwtCfg)
	st := mock.New()
	auditSt := &mockAuditRecorder{}

	h := &Handler{
		store:         st,
		sessionMgr:    sm,
		auditRecorder: auditSt,
		logger:        slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	userID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "unlink@test.com",
		DisplayName: "Unlink Tester",
	})
	for _, acct := range []*store.OAuthAccount{
		{Provider: "telegram", ProviderUserID: "tg-1", UserID: userID},
		{Provider: "yandex", ProviderUserID: "ya-1", UserID: userID},
	} {
		if err := st.CreateOAuthAccount(context.Background(), acct); err != nil {
			t.Fatal(err)
		}
	}

	token, err := sm.IssueToken(userID.String(), "unlink@test.com", "Unlink Tester")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/auth/providers/yandex", nil)
	req.SetPathValue("provider", "yandex")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleUnlinkProvider(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	count, err := st.CountOAuthAccounts(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 linked account after unlink, got %d", count)
	}

	events := auditSt.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "oauth_provider.unlink" {
		t.Errorf("action = %q, want %q", events[0].Action, "oauth_provider.unlink")
	}
	if events[0].Actor != userID.String() {
		t.Errorf("actor = %q, want %q", events[0].Actor, userID.String())
	}
	if events[0].TargetType != "oauth_provider" {
		t.Errorf("target_type = %q, want %q", events[0].TargetType, "oauth_provider")
	}
	if events[0].TargetID != "yandex" {
		t.Errorf("target_id = %q, want %q", events[0].TargetID, "yandex")
	}
}
