package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store/mock"
	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

func testPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// mockAuditStore records audit events in memory.
type mockAuditStore struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *mockAuditStore) Record(_ context.Context, event *audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, *event)
	return nil
}

func (m *mockAuditStore) List(_ context.Context, _ audit.ListFilter) (*audit.ListResult, error) {
	return &audit.ListResult{}, nil
}

func (m *mockAuditStore) Events() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]audit.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

type saTestHarness struct {
	handler    *Handler
	sessionMgr *session.Manager
	mock       *mockAuthzClient
	store      *mock.Store
	auditStore *mockAuditStore
}

func newSATestHarness(t *testing.T) *saTestHarness {
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

	authzMock := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
	}
	st := mock.New()
	auditSt := &mockAuditStore{}

	h := &Handler{
		store:       st,
		sessionMgr:  sm,
		authzClient: &AuthzClient{client: authzMock, logger: slog.Default()},
		auditStore:  auditSt,
		logger:      slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	return &saTestHarness{
		handler:    h,
		sessionMgr: sm,
		mock:       authzMock,
		store:      st,
		auditStore: auditSt,
	}
}

func (th *saTestHarness) issueToken(t *testing.T, userID string) string {
	t.Helper()
	tok, err := th.sessionMgr.IssueToken(userID, "admin@test.com", "Admin")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSA_CreateAndList(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")
	pemStr := testPEM(t)

	body, _ := json.Marshal(createSARequest{
		Name:             "my-sa",
		PublicKeyPEM:     pemStr,
		AllowedAudiences: []string{"aud-a"},
		TokenTTL:         "30m",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.handleCreateServiceAccount(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var created saResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "my-sa" {
		t.Errorf("name = %q, want %q", created.Name, "my-sa")
	}
	if created.Status != "active" {
		t.Errorf("status = %q, want %q", created.Status, "active")
	}

	// List.
	req = httptest.NewRequest(http.MethodGet, "/admin/service-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	th.handler.handleListServiceAccounts(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var list []saResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 SA, got %d", len(list))
	}
	if list[0].Name != "my-sa" {
		t.Errorf("list[0].name = %q, want %q", list[0].Name, "my-sa")
	}
}

func TestSA_GetDetail(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")
	pemStr := testPEM(t)

	body, _ := json.Marshal(createSARequest{
		Name:             "detail-sa",
		PublicKeyPEM:     pemStr,
		AllowedAudiences: []string{"aud-a"},
		TokenTTL:         "15m",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.handleCreateServiceAccount(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/service-accounts/detail-sa", nil)
	req.SetPathValue("name", "detail-sa")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	th.handler.handleGetServiceAccount(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var detail saDetailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.PublicKeyPEM == "" {
		t.Error("detail response should include public_key_pem")
	}
}

func TestSA_Revoke(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")

	body, _ := json.Marshal(createSARequest{
		Name:             "revoke-sa",
		PublicKeyPEM:     testPEM(t),
		AllowedAudiences: []string{"aud-a"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.handleCreateServiceAccount(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/admin/service-accounts/revoke-sa", nil)
	req.SetPathValue("name", "revoke-sa")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	th.handler.handleRevokeServiceAccount(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// List should now be empty (only active SAs).
	req = httptest.NewRequest(http.MethodGet, "/admin/service-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	th.handler.handleListServiceAccounts(w, req)
	var list []saResponse
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Errorf("expected 0 active SAs, got %d", len(list))
	}
}

func TestSA_Rotate(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")

	body, _ := json.Marshal(createSARequest{
		Name:             "rotate-sa",
		PublicKeyPEM:     testPEM(t),
		AllowedAudiences: []string{"aud-a"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.handleCreateServiceAccount(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}

	newPEM := testPEM(t)
	rotateBody, _ := json.Marshal(rotateSARequest{PublicKeyPEM: newPEM})
	req = httptest.NewRequest(http.MethodPost, "/admin/service-accounts/rotate-sa/rotate", bytes.NewReader(rotateBody))
	req.SetPathValue("name", "rotate-sa")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	th.handler.handleRotateServiceAccount(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("rotate: expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify key was updated.
	sa, err := th.store.GetServiceAccount(context.Background(), "rotate-sa")
	if err != nil {
		t.Fatal(err)
	}
	if sa.PublicKeyPEM != newPEM {
		t.Error("public key was not updated")
	}
	if sa.RotatedAt == nil {
		t.Error("rotated_at should be set")
	}
}

func TestSA_PermissionDenied(t *testing.T) {
	th := newSATestHarness(t)
	th.mock.checkAccessFn = func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		return &pb.CheckAccessResponse{Allowed: false}, nil
	}
	token := th.issueToken(t, "unprivileged")

	req := httptest.NewRequest(http.MethodGet, "/admin/service-accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	th.handler.handleListServiceAccounts(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSA_Unauthenticated(t *testing.T) {
	th := newSATestHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/service-accounts", nil)
	w := httptest.NewRecorder()
	th.handler.handleListServiceAccounts(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSA_AuditRecorded(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")

	body, _ := json.Marshal(createSARequest{
		Name:             "audit-sa",
		PublicKeyPEM:     testPEM(t),
		AllowedAudiences: []string{"aud-a"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.handleCreateServiceAccount(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}

	events := th.auditStore.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "service_account.create" {
		t.Errorf("action = %q, want %q", events[0].Action, "service_account.create")
	}
	if events[0].TargetID != "audit-sa" {
		t.Errorf("target_id = %q, want %q", events[0].TargetID, "audit-sa")
	}
	if events[0].Actor != "admin-1" {
		t.Errorf("actor = %q, want %q", events[0].Actor, "admin-1")
	}
}

func TestSA_InvalidPEMRejected(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")

	body, _ := json.Marshal(createSARequest{
		Name:             "bad-pem-sa",
		PublicKeyPEM:     "not-a-pem",
		AllowedAudiences: []string{"aud-a"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.handleCreateServiceAccount(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSA_GetNotFound(t *testing.T) {
	th := newSATestHarness(t)
	token := th.issueToken(t, "admin-1")

	req := httptest.NewRequest(http.MethodGet, "/admin/service-accounts/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	th.handler.handleGetServiceAccount(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
