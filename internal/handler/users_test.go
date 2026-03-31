package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
)

func TestAdminUsers_ListOK(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			if req.Action != permAdminUserLookup {
				t.Errorf("CheckAccess action = %q, want %q", req.Action, permAdminUserLookup)
			}
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	st.SeedUser(&store.User{
		ID:          uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		Email:       "alice@example.com",
		DisplayName: "Alice Admin",
		AvatarURL:   "https://example.com/alice.png",
	})
	st.SeedUser(&store.User{
		ID:          uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		Email:       "bob@example.com",
		DisplayName: "Bob Operator",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/users?q=alice&limit=5", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminUsers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body adminUserListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Limit != 5 {
		t.Fatalf("limit = %d, want 5", body.Limit)
	}
	if len(body.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(body.Users))
	}
	if body.Users[0].Email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", body.Users[0].Email)
	}
	if body.Users[0].DisplayName != "Alice Admin" {
		t.Fatalf("display_name = %q, want Alice Admin", body.Users[0].DisplayName)
	}
}

func TestAdminUsers_ListByID(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	userID := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	st.SeedUser(&store.User{
		ID:          userID,
		Email:       "carol@example.com",
		DisplayName: "Carol",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/users?q="+userID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminUsers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body adminUserListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Users) != 1 || body.Users[0].ID != userID.String() {
		t.Fatalf("unexpected users response: %+v", body.Users)
	}
}

func TestAdminUsers_BadQueryRejected(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	req := httptest.NewRequest(http.MethodGet, "/admin/users?q=a", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminUsers(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminUsers_Forbidden(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: false}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	req := httptest.NewRequest(http.MethodGet, "/admin/users?q=alice", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminUsers(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminUsers_LimitClamped(t *testing.T) {
	authz := &mockAuthzClient{
		checkAccessFn: func(_ context.Context, _ *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {
			return &pb.CheckAccessResponse{Allowed: true}, nil
		},
	}
	h, st, _ := newSessionsHandler(t, authz)
	token := issueSessionsBearer(t, h, st, sessionsTestUserID)

	for i := 0; i < maxAdminUserListLimit+5; i++ {
		st.SeedUser(&store.User{
			ID:          uuid.New(),
			Email:       "sam" + uuid.NewString() + "@example.com",
			DisplayName: "Sam Search",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/users?q=sam&limit=999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.handleListAdminUsers(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body adminUserListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Limit != maxAdminUserListLimit {
		t.Fatalf("limit = %d, want %d", body.Limit, maxAdminUserListLimit)
	}
	if len(body.Users) != maxAdminUserListLimit {
		t.Fatalf("expected %d users, got %d", maxAdminUserListLimit, len(body.Users))
	}
}
