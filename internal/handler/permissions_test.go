package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-core/authnconfig"
	"github.com/ledatu/csar-core/jwtx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
)

// mockAuthzClient implements pb.AuthzServiceClient for testing.
type mockAuthzClient struct {
	pb.AuthzServiceClient

	listSubjectRolesFn  func(ctx context.Context, req *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error)
	listSubjectScopesFn func(ctx context.Context, req *pb.ListSubjectScopesRequest) (*pb.ListSubjectScopesResponse, error)
	listRolePermsFn     func(ctx context.Context, req *pb.ListRolePermissionsRequest) (*pb.ListRolePermissionsResponse, error)
	getRoleFn           func(ctx context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error)
	checkAccessFn       func(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error)
}

func (m *mockAuthzClient) ListSubjectRoles(ctx context.Context, req *pb.ListSubjectRolesRequest, _ ...grpc.CallOption) (*pb.ListSubjectRolesResponse, error) {
	return m.listSubjectRolesFn(ctx, req)
}

func (m *mockAuthzClient) ListSubjectScopes(ctx context.Context, req *pb.ListSubjectScopesRequest, _ ...grpc.CallOption) (*pb.ListSubjectScopesResponse, error) {
	return m.listSubjectScopesFn(ctx, req)
}

func (m *mockAuthzClient) ListRolePermissions(ctx context.Context, req *pb.ListRolePermissionsRequest, _ ...grpc.CallOption) (*pb.ListRolePermissionsResponse, error) {
	return m.listRolePermsFn(ctx, req)
}

func (m *mockAuthzClient) GetRole(ctx context.Context, req *pb.GetRoleRequest, _ ...grpc.CallOption) (*pb.GetRoleResponse, error) {
	return m.getRoleFn(ctx, req)
}

func (m *mockAuthzClient) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest, _ ...grpc.CallOption) (*pb.CheckAccessResponse, error) {
	return m.checkAccessFn(ctx, req)
}

// testHarness bundles a Handler and session manager for permissions tests.
type testHarness struct {
	handler    *Handler
	sessionMgr *session.Manager
	mock       *mockAuthzClient
}

func newTestHarness(t *testing.T) *testHarness {
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

	mock := &mockAuthzClient{}

	h := &Handler{
		sessionMgr:  sm,
		authzClient: &AuthzClient{client: mock, logger: slog.Default()},
		logger:      slog.Default(),
	}
	h.cfg.Store(&config.Config{
		Cookie: config.CookieConfig{Name: "session"},
	})

	return &testHarness{handler: h, sessionMgr: sm, mock: mock}
}

func (th *testHarness) issueToken(t *testing.T, userID string) string {
	t.Helper()
	tok, err := th.sessionMgr.IssueToken(userID, "test@example.com", "Test User")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (th *testHarness) permissionsRequest(t *testing.T, token, queryString string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/auth/me/permissions"
	if queryString != "" {
		url += "?" + queryString
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	th.handler.handlePermissions(w, req)
	return w
}

func (th *testHarness) checkRequest(t *testing.T, token, queryString string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/me/check?"+queryString, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	th.handler.handleCheck(w, req)
	return w
}

// ─── Fixtures ────────────────────────────────────────────────────────────────

// setupStandardMock wires the mock with:
//   - platform scope: role "platform_admin" with permission platform.roles.create:admin
//   - tenant "t-123": role "tenant_manager" with permission tenant.members.read:admin
//
// All roles have no parents.
func setupStandardMock(mock *mockAuthzClient) {
	mock.listSubjectScopesFn = func(_ context.Context, _ *pb.ListSubjectScopesRequest) (*pb.ListSubjectScopesResponse, error) {
		return &pb.ListSubjectScopesResponse{
			Scopes: []*pb.SubjectScope{
				{ScopeType: "platform", ScopeId: ""},
				{ScopeType: "tenant", ScopeId: "t-123"},
			},
		}, nil
	}

	mock.listSubjectRolesFn = func(_ context.Context, req *pb.ListSubjectRolesRequest) (*pb.ListSubjectRolesResponse, error) {
		switch {
		case req.ScopeType == "platform":
			return &pb.ListSubjectRolesResponse{Roles: []string{"platform_admin"}}, nil
		case req.ScopeType == "tenant" && req.ScopeId == "t-123":
			return &pb.ListSubjectRolesResponse{Roles: []string{"tenant_manager"}}, nil
		default:
			return &pb.ListSubjectRolesResponse{}, nil
		}
	}

	mock.getRoleFn = func(_ context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error) {
		return &pb.GetRoleResponse{
			Role: &pb.Role{Name: req.Name},
		}, nil
	}

	mock.listRolePermsFn = func(_ context.Context, req *pb.ListRolePermissionsRequest) (*pb.ListRolePermissionsResponse, error) {
		switch req.Role {
		case "platform_admin":
			return &pb.ListRolePermissionsResponse{
				Permissions: []*pb.Permission{
					{Action: "platform.roles.create", Resource: "admin"},
				},
			}, nil
		case "tenant_manager":
			return &pb.ListRolePermissionsResponse{
				Permissions: []*pb.Permission{
					{Action: "tenant.members.read", Resource: "admin"},
				},
			}, nil
		default:
			return &pb.ListRolePermissionsResponse{}, nil
		}
	}

	mock.checkAccessFn = func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		return &pb.CheckAccessResponse{
			Allowed:      true,
			MatchedRoles: []string{"platform_admin"},
		}, nil
	}
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestPermissions_FullDiscovery(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)
	token := th.issueToken(t, "user-1")

	w := th.permissionsRequest(t, token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp permissionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Subject != "user-1" {
		t.Errorf("subject = %q, want %q", resp.Subject, "user-1")
	}
	if resp.Platform == nil {
		t.Fatal("platform is nil")
	}
	if len(resp.Platform.Roles) != 1 || resp.Platform.Roles[0] != "platform_admin" {
		t.Errorf("platform roles = %v, want [platform_admin]", resp.Platform.Roles)
	}
	if len(resp.Platform.Permissions) != 1 || resp.Platform.Permissions[0].Action != "platform.roles.create" {
		t.Errorf("platform permissions = %v, want [{platform.roles.create admin}]", resp.Platform.Permissions)
	}
	if resp.Tenants == nil || resp.Tenants["t-123"] == nil {
		t.Fatal("tenants[t-123] is nil")
	}
	tp := resp.Tenants["t-123"]
	if len(tp.Roles) != 1 || tp.Roles[0] != "tenant_manager" {
		t.Errorf("tenant roles = %v, want [tenant_manager]", tp.Roles)
	}
	if len(tp.Permissions) != 1 || tp.Permissions[0].Action != "tenant.members.read" {
		t.Errorf("tenant permissions = %v, want [{tenant.members.read admin}]", tp.Permissions)
	}
}

func TestPermissions_ScopedPlatform(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)
	token := th.issueToken(t, "user-1")

	w := th.permissionsRequest(t, token, "scope_type=platform")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp permissionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Platform == nil {
		t.Fatal("platform is nil for scoped platform query")
	}
	if resp.Tenants != nil {
		t.Errorf("tenants should be nil for scoped platform query, got %v", resp.Tenants)
	}
	if len(resp.Platform.Roles) != 1 || resp.Platform.Roles[0] != "platform_admin" {
		t.Errorf("platform roles = %v, want [platform_admin]", resp.Platform.Roles)
	}
}

func TestPermissions_ScopedTenant(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)
	token := th.issueToken(t, "user-1")

	w := th.permissionsRequest(t, token, "scope_type=tenant&scope_id=t-123")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp permissionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Platform != nil {
		t.Errorf("platform should be nil for scoped tenant query, got %v", resp.Platform)
	}
	if resp.Tenants == nil || resp.Tenants["t-123"] == nil {
		t.Fatal("tenants[t-123] is nil for scoped tenant query")
	}
	tp := resp.Tenants["t-123"]
	if len(tp.Roles) != 1 || tp.Roles[0] != "tenant_manager" {
		t.Errorf("tenant roles = %v, want [tenant_manager]", tp.Roles)
	}
}

func TestPermissions_TenantWithoutScopeID(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)
	token := th.issueToken(t, "user-1")

	w := th.permissionsRequest(t, token, "scope_type=tenant")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPermissions_InvalidScopeType(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)
	token := th.issueToken(t, "user-1")

	w := th.permissionsRequest(t, token, "scope_type=invalid")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPermissions_Unauthenticated(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)

	req := httptest.NewRequest(http.MethodGet, "/auth/me/permissions", nil)
	w := httptest.NewRecorder()
	th.handler.handlePermissions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestPermissions_NoAssignments(t *testing.T) {
	th := newTestHarness(t)
	th.mock.listSubjectScopesFn = func(_ context.Context, _ *pb.ListSubjectScopesRequest) (*pb.ListSubjectScopesResponse, error) {
		return &pb.ListSubjectScopesResponse{}, nil
	}
	token := th.issueToken(t, "user-1")

	w := th.permissionsRequest(t, token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp permissionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Platform != nil {
		t.Errorf("platform should be nil, got %v", resp.Platform)
	}
	if resp.Tenants != nil {
		t.Errorf("tenants should be nil, got %v", resp.Tenants)
	}
}

func TestCheck_WithScopeParams(t *testing.T) {
	th := newTestHarness(t)

	var capturedReq *pb.CheckAccessRequest
	th.mock.checkAccessFn = func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		capturedReq = req
		return &pb.CheckAccessResponse{Allowed: true, MatchedRoles: []string{"platform_admin"}}, nil
	}
	token := th.issueToken(t, "user-1")

	w := th.checkRequest(t, token, "resource=/admin&action=GET&scope_type=platform")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if capturedReq.ScopeType != "platform" {
		t.Errorf("scope_type = %q, want %q", capturedReq.ScopeType, "platform")
	}
	if capturedReq.Subject != "user-1" {
		t.Errorf("subject = %q, want %q", capturedReq.Subject, "user-1")
	}
}

func TestCheck_WithTenantScope(t *testing.T) {
	th := newTestHarness(t)

	var capturedReq *pb.CheckAccessRequest
	th.mock.checkAccessFn = func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		capturedReq = req
		return &pb.CheckAccessResponse{Allowed: true}, nil
	}
	token := th.issueToken(t, "user-1")

	w := th.checkRequest(t, token, "resource=/tenants/t-123/members&action=GET&scope_type=tenant&scope_id=t-123")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if capturedReq.ScopeType != "tenant" {
		t.Errorf("scope_type = %q, want %q", capturedReq.ScopeType, "tenant")
	}
	if capturedReq.ScopeId != "t-123" {
		t.Errorf("scope_id = %q, want %q", capturedReq.ScopeId, "t-123")
	}
}

func TestCheck_WithoutScope(t *testing.T) {
	th := newTestHarness(t)

	var capturedReq *pb.CheckAccessRequest
	th.mock.checkAccessFn = func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
		capturedReq = req
		return &pb.CheckAccessResponse{Allowed: false}, nil
	}
	token := th.issueToken(t, "user-1")

	w := th.checkRequest(t, token, "resource=/data&action=GET")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if capturedReq.ScopeType != "" {
		t.Errorf("scope_type should be empty, got %q", capturedReq.ScopeType)
	}
	if capturedReq.ScopeId != "" {
		t.Errorf("scope_id should be empty, got %q", capturedReq.ScopeId)
	}
}

func TestCheck_InvalidScopeType(t *testing.T) {
	th := newTestHarness(t)
	setupStandardMock(th.mock)
	token := th.issueToken(t, "user-1")

	w := th.checkRequest(t, token, "resource=/data&action=GET&scope_type=bad")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
