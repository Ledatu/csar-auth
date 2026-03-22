package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

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
// otherwise plaintext gRPC is used. If tokenSource is non-nil, every RPC
// automatically carries a Bearer token via the authorization metadata header.
func NewAuthzClient(endpoint string, tlsCfg config.AuthzTLSConfig, tokenSource credentials.PerRPCCredentials, logger *slog.Logger) (*AuthzClient, error) {
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

	if tokenSource != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(tokenSource))
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

// scopedPermissions holds roles and permissions for a single scope.
type scopedPermissions struct {
	Roles       []string          `json:"roles"`
	Permissions []permissionEntry `json:"permissions"`
}

// permissionsResponse is the JSON response for GET /auth/me/permissions.
// Keys are omitted when the user has no assignments in that scope category.
type permissionsResponse struct {
	Subject  string                        `json:"subject"`
	Platform *scopedPermissions            `json:"platform,omitempty"`
	Tenants  map[string]*scopedPermissions `json:"tenants,omitempty"`
}

// checkResponse is the JSON response for GET /auth/me/check.
type checkResponse struct {
	Allowed      bool     `json:"allowed"`
	MatchedRoles []string `json:"matched_roles,omitempty"`
}

var validScopeTypes = map[string]struct{}{
	"platform": {},
	"tenant":   {},
}

// parseScopeParams extracts and validates scope_type / scope_id query params.
// Returns ("", "", nil) when no scope filter was requested.
func parseScopeParams(r *http.Request) (scopeType, scopeID string, err error) {
	scopeType = r.URL.Query().Get("scope_type")
	if scopeType == "" {
		return "", "", nil
	}
	if _, ok := validScopeTypes[scopeType]; !ok {
		return "", "", fmt.Errorf("scope_type must be %q or %q", "platform", "tenant")
	}
	scopeID = r.URL.Query().Get("scope_id")
	if scopeType == "tenant" && scopeID == "" {
		return "", "", fmt.Errorf("scope_id is required when scope_type is %q", "tenant")
	}
	return scopeType, scopeID, nil
}

// handlePermissions returns the authenticated user's scoped roles and effective permissions.
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

	scopeType, scopeID, err := parseScopeParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	resp := permissionsResponse{Subject: subject}

	if scopeType != "" {
		sp, err := h.resolveScope(ctx, subject, scopeType, scopeID)
		if err != nil {
			h.logger.Error("failed to resolve scope", "subject", subject, "scope_type", scopeType, "scope_id", scopeID, "error", err)
			http.Error(w, "failed to fetch permissions", http.StatusBadGateway)
			return
		}
		h.attachScope(&resp, scopeType, scopeID, sp)
	} else {
		scopesResp, err := h.authzClient.client.ListSubjectScopes(ctx, &pb.ListSubjectScopesRequest{
			Subject: subject,
		})
		if err != nil {
			h.logger.Error("failed to list subject scopes", "subject", subject, "error", err)
			http.Error(w, "failed to fetch permissions", http.StatusBadGateway)
			return
		}
		for _, sc := range scopesResp.Scopes {
			sp, err := h.resolveScope(ctx, subject, sc.ScopeType, sc.ScopeId)
			if err != nil {
				h.logger.Warn("failed to resolve scope, skipping", "subject", subject, "scope_type", sc.ScopeType, "scope_id", sc.ScopeId, "error", err)
				continue
			}
			h.attachScope(&resp, sc.ScopeType, sc.ScopeId, sp)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveScope fetches roles and permissions for a single (scopeType, scopeID) pair.
func (h *Handler) resolveScope(ctx context.Context, subject, scopeType, scopeID string) (*scopedPermissions, error) {
	rolesResp, err := h.authzClient.client.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject:   subject,
		ScopeType: scopeType,
		ScopeId:   scopeID,
	})
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	effectiveRoles := h.collectEffectiveRoles(ctx, rolesResp.Roles)

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

	return &scopedPermissions{
		Roles:       effectiveRoles,
		Permissions: permissions,
	}, nil
}

// attachScope places resolved permissions into the correct response field.
func (h *Handler) attachScope(resp *permissionsResponse, scopeType, scopeID string, sp *scopedPermissions) {
	switch scopeType {
	case "platform":
		resp.Platform = sp
	case "tenant":
		if resp.Tenants == nil {
			resp.Tenants = make(map[string]*scopedPermissions)
		}
		resp.Tenants[scopeID] = sp
	}
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

	q := r.URL.Query()
	resource := q.Get("resource")
	action := q.Get("action")
	if resource == "" || action == "" {
		http.Error(w, "resource and action query parameters are required", http.StatusBadRequest)
		return
	}

	scopeType, scopeID, err := parseScopeParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if scopeType == "" {
		scopeType = "platform"
	}

	resp, err := h.authzClient.client.CheckAccess(r.Context(), &pb.CheckAccessRequest{
		Subject:   subject,
		Resource:  resource,
		Action:    action,
		ScopeType: scopeType,
		ScopeId:   scopeID,
	})
	if err != nil {
		h.logger.Error("failed to check access", "subject", subject, "resource", resource, "action", action, "error", err)
		http.Error(w, "failed to check access", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	_ = json.NewEncoder(w).Encode(checkResponse{
		Allowed:      resp.Allowed,
		MatchedRoles: resp.MatchedRoles,
	})
}

// extractSubject returns the user's subject ID from either Bearer JWT or
// session cookie. Returns empty string if not authenticated.
func (h *Handler) extractSubject(r *http.Request) string {
	_, user, ok := h.resolveAuth(r)
	if !ok {
		return ""
	}
	return user.ID.String()
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
