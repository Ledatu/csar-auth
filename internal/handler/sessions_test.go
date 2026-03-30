package handler

import (
	"context"
	"encoding/json"
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
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

func newSessionsHandler(t *testing.T, authz *mockAuthzClient) (*Handler, *mock.Store, *session.SessionManager) {
	t.Helper()

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
	sessMgr := session.NewSessionManager(st, slog.Default(), 24*time.Hour, 7*24*time.Hour, time.Minute)

	var ac *AuthzClient
	if authz != nil {
		ac = &AuthzClient{client: authz, logger: slog.Default()}
	}

	h := &Handler{
		store:       st,
		sessionMgr:  sm,
		sessMgr:     sessMgr,
		authzClient: ac,
		logger:      slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})
	return h, st, sessMgr
}

var sessionsTestUserID = uuid.MustParse("11111111-1111-4111-8111-111111111111")

func issueSessionsBearer(t *testing.T, h *Handler, st *mock.Store, userID uuid.UUID) string {
	t.Helper()
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "sessions@test.com",
		DisplayName: "Sessions Tester",
	})
	tok, err := h.sessionMgr.IssueToken(userID.String(), "sessions@test.com", "Sessions Tester")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestAdminSessions_ListOK(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			if req.Action != permSessionsRead {
				t.Errorf("CheckAccess action = %q, want %q", req.Action, permSessionsRead)
			}
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	now := time.Now().UTC()
	_ = st.CreateSession(context.Background(), &store.Session{
		ID:         "sess-a",
		UserID:     sessionsTestUserID,
		CreatedAt:  now.Add(-2 * time.Hour),
		LastSeenAt: now.Add(-30 * time.Minute),
		ExpiresAt:  now.Add(24 * time.Hour),
		UserAgent:  "ua-test",
		IPAddress:  "127.0.0.1",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Sessions []sessionListItem `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(body.Sessions))
	}
	if body.Sessions[0].SessionID == "sess-a" {
		t.Fatal("session_id leaked raw session secret")
	}
	if body.Sessions[0].SessionID != safeSessionID("sess-a") {
		t.Errorf("session_id = %q, want safe id", body.Sessions[0].SessionID)
	}
	if body.Sessions[0].Email != "sessions@test.com" {
		t.Errorf("email = %q", body.Sessions[0].Email)
	}
	if !body.Sessions[0].IsActive {
		t.Error("expected IsActive true")
	}
}

func TestAdminSessions_Forbidden(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: false}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminSessions(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMeSessions_CookieMarksCurrent(t *testing.T) {
	h, st, sessMgr := newSessionsHandler(t, nil)
	uid := sessionsTestUserID
	st.SeedUser(&store.User{
		ID:          uid,
		Email:       "me@test.com",
		DisplayName: "Me",
	})

	sessA, err := sessMgr.Create(context.Background(), uid, "ua-1", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	sessB, err := sessMgr.Create(context.Background(), uid, "ua-2", "10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/me/sessions", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessA.ID})
	w := httptest.NewRecorder()
	h.handleMeSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Sessions []sessionListItem `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(body.Sessions))
	}
	var nCurrent int
	for _, s := range body.Sessions {
		if s.IsCurrent {
			nCurrent++
			if s.SessionID != safeSessionID(sessA.ID) {
				t.Errorf("wrong current session: %q", s.SessionID)
			}
		}
	}
	if nCurrent != 1 {
		t.Errorf("expected exactly one is_current, got %d", nCurrent)
	}
	if sessB.ID == "" {
		t.Fatal("sessB id empty")
	}
}

func TestMeSessions_BearerAddsSyntheticCurrentWhenNoSessionRow(t *testing.T) {
	h, st, _ := newSessionsHandler(t, nil)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	req := httptest.NewRequest(http.MethodGet, "/auth/me/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "bearer-client")
	w := httptest.NewRecorder()
	h.handleMeSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Sessions []sessionListItem `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(body.Sessions))
	}
	if !body.Sessions[0].IsCurrent {
		t.Fatal("expected synthetic bearer session to be current")
	}
	if body.Sessions[0].SessionID != safeSessionID(token) {
		t.Fatalf("session_id = %q, want safe bearer id", body.Sessions[0].SessionID)
	}
	if body.Sessions[0].UserAgent != "bearer-client" {
		t.Fatalf("user_agent = %q", body.Sessions[0].UserAgent)
	}
}
