package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-core/tlsx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// AuthzClient wraps a gRPC connection to csar-authz.
type AuthzClient struct {
	conn   *grpc.ClientConn
	client pb.AuthzServiceClient
	logger *slog.Logger
}

// NewAuthzClient connects to csar-authz at the given endpoint.
// When tlsCfg.Enabled is true it establishes a TLS (optionally mTLS) connection;
// otherwise plaintext gRPC is used.
func NewAuthzClient(endpoint string, tlsCfg config.AuthzTLSConfig, logger *slog.Logger) (*AuthzClient, error) {
	var opts []grpc.DialOption
	if !tlsCfg.Enabled {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tc, err := tlsx.NewClientTLSConfig(tlsx.ClientConfig{
			CAFile:   tlsCfg.CAFile,
			CertFile: tlsCfg.CertFile,
			KeyFile:  tlsCfg.KeyFile,
		})
		if err != nil {
			return nil, fmt.Errorf("building authz TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	}

	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return nil, err
	}

	return &AuthzClient{
		conn:   conn,
		client: pb.NewAuthzServiceClient(conn),
		logger: logger,
	}, nil
}

// Close closes the gRPC connection.
func (c *AuthzClient) Close() error {
	return c.conn.Close()
}

// permissionEntry is a single permission in the REST response.
type permissionEntry struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// permissionsResponse is the JSON response for GET /auth/me/permissions.
type permissionsResponse struct {
	Subject     string            `json:"subject"`
	Roles       []string          `json:"roles"`
	Permissions []permissionEntry `json:"permissions"`
}

// checkResponse is the JSON response for GET /auth/me/check.
type checkResponse struct {
	Allowed      bool     `json:"allowed"`
	MatchedRoles []string `json:"matched_roles,omitempty"`
}

// handlePermissions returns the authenticated user's roles and effective permissions.
func (h *Handler) handlePermissions(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if h.authzClient == nil {
		http.Error(w, "authorization service not configured", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()

	// Get the subject's directly assigned roles.
	rolesResp, err := h.authzClient.client.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject: subject,
	})
	if err != nil {
		h.logger.Error("failed to list subject roles", "subject", subject, "error", err)
		http.Error(w, "failed to fetch roles", http.StatusBadGateway)
		return
	}

	// Collect all effective roles (including inherited via parents).
	effectiveRoles := h.collectEffectiveRoles(ctx, rolesResp.Roles)

	// Collect permissions from all effective roles.
	var permissions []permissionEntry
	seen := make(map[string]struct{})
	for _, roleName := range effectiveRoles {
		permsResp, err := h.authzClient.client.ListRolePermissions(ctx, &pb.ListRolePermissionsRequest{
			Role: roleName,
		})
		if err != nil {
			h.logger.Warn("failed to list role permissions", "role", roleName, "error", err)
			continue
		}
		for _, p := range permsResp.Permissions {
			key := p.Action + ":" + p.Resource
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			permissions = append(permissions, permissionEntry{
				Action:   p.Action,
				Resource: p.Resource,
			})
		}
	}

	resp := permissionsResponse{
		Subject:     subject,
		Roles:       effectiveRoles,
		Permissions: permissions,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	json.NewEncoder(w).Encode(resp)
}

// handleCheck performs a single access check for the authenticated user.
func (h *Handler) handleCheck(w http.ResponseWriter, r *http.Request) {
	subject := h.extractSubject(r)
	if subject == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	if h.authzClient == nil {
		http.Error(w, "authorization service not configured", http.StatusServiceUnavailable)
		return
	}

	resource := r.URL.Query().Get("resource")
	action := r.URL.Query().Get("action")
	if resource == "" || action == "" {
		http.Error(w, "resource and action query parameters are required", http.StatusBadRequest)
		return
	}

	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:  subject,
		Resource: resource,
		Action:   action,
	})
	if err != nil {
		h.logger.Error("failed to check access", "subject", subject, "resource", resource, "action", action, "error", err)
		http.Error(w, "failed to check access", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	json.NewEncoder(w).Encode(checkResponse{
		Allowed:      resp.Allowed,
		MatchedRoles: resp.MatchedRoles,
	})
}

// extractSubject returns the user's subject ID from either:
// 1. Authorization: Bearer <token> header (verified via sessionMgr)
// 2. Session cookie
// Returns empty string if not authenticated.
func (h *Handler) extractSubject(r *http.Request) string {
	// Try Authorization header first (for API clients like csar-ts).
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := h.sessionMgr.VerifyToken(token)
		if err == nil {
			return claims.Sub
		}
		h.logger.Debug("bearer token verification failed", "error", err)
	}

	// Fall back to session cookie.
	cookie, err := r.Cookie(h.cfg.Cookie.Name)
	if err != nil {
		return ""
	}
	claims, err := h.sessionMgr.VerifyToken(cookie.Value)
	if err != nil {
		return ""
	}
	return claims.Sub
}

// collectEffectiveRoles resolves role hierarchy by walking parent roles.
func (h *Handler) collectEffectiveRoles(ctx context.Context, directRoles []string) []string {
	seen := make(map[string]struct{})
	var result []string

	var walk func(roleName string)
	walk = func(roleName string) {
		if _, ok := seen[roleName]; ok {
			return
		}
		seen[roleName] = struct{}{}
		result = append(result, roleName)

		// Resolve parents.
		roleResp, err := h.authzClient.client.GetRole(ctx, &pb.GetRoleRequest{Name: roleName})
		if err != nil {
			h.logger.Warn("failed to get role for hierarchy resolution", "role", roleName, "error", err)
			return
		}
		for _, parent := range roleResp.Role.Parents {
			walk(parent)
		}
	}

	for _, role := range directRoles {
		walk(role)
	}
	return result
}
