package botverify

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/gatewayctx"

	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func testConfig() *authnconfig.Config {
	return &authnconfig.Config{
		Cookie: authnconfig.CookieConfig{
			Name:     "csar_session",
			Domain:   "localhost",
			Secure:   false,
			SameSite: "lax",
		},
		BotVerify: &authnconfig.BotVerifyConfig{
			Enabled:          true,
			CodeTTL:          authnconfig.NewDuration(5 * time.Minute),
			MaxPendingPerIP:  3,
			AllowedProviders: []string{"telegram", "vk"},
			Bots: []authnconfig.BotProviderInfo{
				{Provider: "telegram", BotUsername: "@TestBot"},
			},
		},
	}
}

func testHandler() (*Handler, *mock.Store) {
	st := mock.New()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	sessMgr := session.NewSessionManager(st, logger, 24*time.Hour, 7*24*time.Hour, time.Minute)
	cfg := testConfig()
	h := NewHandler(st, sessMgr, nil, cfg, logger)
	return h, st
}

func TestHandleStart_Login(t *testing.T) {
	h, _ := testHandler()

	req := httptest.NewRequest(http.MethodPost, "/auth/bot-verify/start", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()

	h.HandleStart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["intent"] != "login" {
		t.Fatalf("intent = %v, want login", resp["intent"])
	}
	if resp["code"] == nil || resp["code"] == "" {
		t.Fatal("expected non-empty code")
	}
	code := resp["code"].(string)
	if len(code) != codeLength {
		t.Fatalf("code length = %d, want %d", len(code), codeLength)
	}
	if resp["verification_id"] == nil {
		t.Fatal("expected verification_id")
	}
}

func TestHandleStart_RateLimit(t *testing.T) {
	h, _ := testHandler()

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/bot-verify/start", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		h.HandleStart(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/bot-verify/start", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	h.HandleStart(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: status = %d, want 429", w.Code)
	}
}

func TestHandleStatus_Pending(t *testing.T) {
	h, st := testHandler()

	v := &store.BotVerification{
		ID:        uuid.New(),
		CodeHash:  hashCode("TESTCD"),
		Intent:    "login",
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := st.CreateBotVerification(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/bot-verify/status/{id}", h.HandleStatus)
	req := httptest.NewRequest(http.MethodGet, "/auth/bot-verify/status/"+v.ID.String(), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "pending" {
		t.Fatalf("status = %q, want pending", resp["status"])
	}
}

func TestHandleStatus_Expired(t *testing.T) {
	h, st := testHandler()

	v := &store.BotVerification{
		ID:        uuid.New(),
		CodeHash:  hashCode("TESTCD"),
		Intent:    "login",
		Status:    "pending",
		CreatedAt: time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	}
	if err := st.CreateBotVerification(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/bot-verify/status/{id}", h.HandleStatus)
	req := httptest.NewRequest(http.MethodGet, "/auth/bot-verify/status/"+v.ID.String(), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "expired" {
		t.Fatalf("status = %q, want expired", resp["status"])
	}
}

func TestHandleConfirm_Success(t *testing.T) {
	h, st := testHandler()

	code := "A7X9K2"
	v := &store.BotVerification{
		ID:        uuid.New(),
		CodeHash:  hashCode(code),
		Intent:    "login",
		Status:    "pending",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := st.CreateBotVerification(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{
		"code":             code,
		"provider":         "telegram",
		"provider_user_id": "12345",
		"display_name":     "Test User",
	})

	req := httptest.NewRequest(http.MethodPost, "/svc/authn/bot-verify/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := gatewayctx.NewContext(req.Context(), &gatewayctx.Identity{Subject: "svc:csar-botverify"})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.HandleConfirm(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	got, _ := st.GetBotVerification(context.Background(), v.ID)
	if got.Status != "confirmed" {
		t.Fatalf("verification status = %q, want confirmed", got.Status)
	}
	if got.ProviderUserID != "12345" {
		t.Fatalf("provider_user_id = %q, want 12345", got.ProviderUserID)
	}
}

func TestHandleConfirm_ForbiddenWithoutIdentity(t *testing.T) {
	h, _ := testHandler()

	body, _ := json.Marshal(map[string]string{
		"code": "A7X9K2", "provider": "telegram", "provider_user_id": "12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/svc/authn/bot-verify/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	h.HandleConfirm(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestHandleConfirm_DisallowedProvider(t *testing.T) {
	h, _ := testHandler()

	body, _ := json.Marshal(map[string]string{
		"code": "A7X9K2", "provider": "unknown", "provider_user_id": "12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/svc/authn/bot-verify/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := gatewayctx.NewContext(req.Context(), &gatewayctx.Identity{Subject: "svc:csar-botverify"})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.HandleConfirm(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestFinalizeLogin(t *testing.T) {
	h, st := testHandler()

	code := "B3Y7M5"
	v := &store.BotVerification{
		ID:              uuid.New(),
		CodeHash:        hashCode(code),
		Intent:          "login",
		Status:          "confirmed",
		Provider:        "telegram",
		ProviderUserID:  "67890",
		ProviderDisplay: "Alice",
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
	}
	now := time.Now()
	v.ConfirmedAt = &now
	if err := st.CreateBotVerification(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	// Override status to "confirmed" since mock CreateBotVerification stores as-is.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/bot-verify/finalize/{id}", h.HandleFinalize)
	req := httptest.NewRequest(http.MethodPost, "/auth/bot-verify/finalize/"+v.ID.String(), nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["result"] != "authenticated" {
		t.Fatalf("result = %v, want authenticated", resp["result"])
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "csar_session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected session cookie to be set")
	}
}

func TestFinalizeLink(t *testing.T) {
	h, st := testHandler()

	user := &store.User{
		ID:          uuid.New(),
		DisplayName: "Bob",
	}
	st.SeedUser(user)

	sess := &store.Session{
		ID:         "sess-123",
		UserID:     user.ID,
		CreatedAt:  time.Now(),
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	_ = st.CreateSession(context.Background(), sess)

	code := "C4Z8N6"
	v := &store.BotVerification{
		ID:              uuid.New(),
		CodeHash:        hashCode(code),
		Intent:          "link",
		UserID:          &user.ID,
		Status:          "confirmed",
		Provider:        "telegram",
		ProviderUserID:  "99999",
		ProviderDisplay: "BobTG",
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
	}
	now := time.Now()
	v.ConfirmedAt = &now
	_ = st.CreateBotVerification(context.Background(), v)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/bot-verify/finalize/{id}", h.HandleFinalize)
	req := httptest.NewRequest(http.MethodPost, "/auth/bot-verify/finalize/"+v.ID.String(), nil)
	req.AddCookie(&http.Cookie{Name: "csar_session", Value: "sess-123"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["result"] != "linked" {
		t.Fatalf("result = %v, want linked", resp["result"])
	}
}

func TestFinalizeLinkMerge(t *testing.T) {
	h, st := testHandler()

	otherUser := &store.User{ID: uuid.New(), DisplayName: "OtherUser"}
	st.SeedUser(otherUser)
	_ = st.CreateOAuthAccount(context.Background(), &store.OAuthAccount{
		Provider:       "telegram",
		ProviderUserID: "conflict-id",
		UserID:         otherUser.ID,
	})

	targetUser := &store.User{ID: uuid.New(), DisplayName: "Target"}
	st.SeedUser(targetUser)

	sess := &store.Session{
		ID:         "sess-merge",
		UserID:     targetUser.ID,
		CreatedAt:  time.Now(),
		LastSeenAt: time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	_ = st.CreateSession(context.Background(), sess)

	v := &store.BotVerification{
		ID:              uuid.New(),
		CodeHash:        hashCode("MERGE1"),
		Intent:          "link",
		UserID:          &targetUser.ID,
		Status:          "confirmed",
		Provider:        "telegram",
		ProviderUserID:  "conflict-id",
		ProviderDisplay: "OtherTG",
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(5 * time.Minute),
	}
	now := time.Now()
	v.ConfirmedAt = &now
	_ = st.CreateBotVerification(context.Background(), v)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/bot-verify/finalize/{id}", h.HandleFinalize)
	req := httptest.NewRequest(http.MethodPost, "/auth/bot-verify/finalize/"+v.ID.String(), nil)
	req.AddCookie(&http.Cookie{Name: "csar_session", Value: "sess-merge"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["result"] != "merge_available" {
		t.Fatalf("result = %v, want merge_available", resp["result"])
	}
	if resp["merge_ready"] != true {
		t.Fatal("expected merge_ready=true")
	}

	mergeCookie := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == "csar_merge" {
			mergeCookie = c.Value
		}
	}
	if mergeCookie == "" {
		t.Fatal("expected csar_merge cookie to be set")
	}
}

func TestGenerateCode(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generateCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != codeLength {
			t.Fatalf("code length = %d, want %d", len(code), codeLength)
		}
		for _, ch := range code {
			if ch == '0' || ch == 'O' || ch == '1' || ch == 'I' || ch == 'L' {
				t.Fatalf("code %q contains ambiguous character %c", code, ch)
			}
		}
		if seen[code] {
			t.Fatalf("duplicate code %q in 100 iterations", code)
		}
		seen[code] = true
	}
}

func TestHashCode_CaseInsensitive(t *testing.T) {
	h1 := hashCode("A7X9K2")
	h2 := hashCode("a7x9k2")
	h3 := hashCode(" A7X9K2 ")
	if h1 != h2 {
		t.Fatal("hashCode should be case-insensitive")
	}
	if h1 != h3 {
		t.Fatal("hashCode should trim whitespace")
	}
}
