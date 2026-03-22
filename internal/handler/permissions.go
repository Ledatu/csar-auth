package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-core/tlsx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultRoleCacheTTL = 30 * time.Second

// cachedRole holds pre-fetched role metadata (parents + permissions).
type cachedRole struct {
	Parents     []string
	Permissions []permissionEntry
}

// roleSnapshot is an immutable point-in-time snapshot of all role definitions.
type roleSnapshot struct {
	roles   map[string]*cachedRole
	builtAt time.Time
}

// AuthzClient wraps a gRPC connection to csar-authz.
type AuthzClient struct {
	conn   *grpc.ClientConn
	client pb.AuthzServiceClient
	logger *slog.Logger

	snapshot atomic.Pointer[roleSnapshot]
	sflight  singleflight.Group
	cacheTTL time.Duration
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
		conn:     conn,
		client:   pb.NewAuthzServiceClient(conn),
		logger:   logger,
		cacheTTL: defaultRoleCacheTTL,
	}, nil
}

// Close closes the gRPC connection.
func (c *AuthzClient) Close() error {
	return c.conn.Close()
}

// getSnapshot returns the current role snapshot, refreshing it if stale.
// Concurrent callers share one in-flight refresh via singleflight.
func (c *AuthzClient) getSnapshot(ctx context.Context) (*roleSnapshot, error) {
	if snap := c.snapshot.Load(); snap != nil && time.Since(snap.builtAt) < c.cacheTTL {
		return snap, nil
	}

	v, err, _ := c.sflight.Do("refresh", func() (interface{}, error) {
		// Double-check: another goroutine may have refreshed while we waited.
		if snap := c.snapshot.Load(); snap != nil && time.Since(snap.builtAt) < c.cacheTTL {
			return snap, nil
		}
		return c.buildSnapshot(ctx)
	})
	if err != nil {
		return nil, err
	}
	return v.(*roleSnapshot), nil
}

// buildSnapshot fetches all roles and their permissions, building an immutable snapshot.
func (c *AuthzClient) buildSnapshot(ctx context.Context) (*roleSnapshot, error) {
	rolesResp, err := c.client.ListRoles(ctx, &pb.ListRolesRequest{})
	if err != nil {
		return nil, fmt.Errorf("listing all roles: %w", err)
	}

	snap := &roleSnapshot{
		roles:   make(map[string]*cachedRole, len(rolesResp.Roles)),
		builtAt: time.Now(),
	}

	// Pre-populate parents from ListRoles (permissions filled below).
	for _, r := range rolesResp.Roles {
		snap.roles[r.Name] = &cachedRole{Parents: r.Parents}
	}

	// Fetch permissions for each role in parallel.
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(25)
	for _, r := range rolesResp.Roles {
		roleName := r.Name
		g.Go(func() error {
			permsResp, err := c.client.ListRolePermissions(gCtx, &pb.ListRolePermissionsRequest{Role: roleName})
			if err != nil {
				c.logger.Warn("cache: failed to list role permissions", "role", roleName, "error", err)
				return nil
			}
			perms := make([]permissionEntry, len(permsResp.Permissions))
			for i, p := range permsResp.Permissions {
				perms[i] = permissionEntry{Action: p.Action, Resource: p.Resource}
			}
			snap.roles[roleName].Permissions = perms
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	c.snapshot.Store(snap)
	c.logger.Info("role cache refreshed", "roles", len(snap.roles))
	return snap, nil
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

	snap, err := h.authzClient.getSnapshot(ctx)
	if err != nil {
		h.logger.Error("failed to load role cache", "error", err)
		http.Error(w, "failed to fetch permissions", http.StatusBadGateway)
		return
	}

	resp := permissionsResponse{Subject: subject}

	if scopeType != "" {
		sp, err := h.resolveScope(ctx, snap, subject, scopeType, scopeID)
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

		type scopeResult struct {
			scopeType, scopeID string
			sp                 *scopedPermissions
		}
		results := make([]scopeResult, len(scopesResp.Scopes))

		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(50)
		for i, sc := range scopesResp.Scopes {
			results[i].scopeType = sc.ScopeType
			results[i].scopeID = sc.ScopeId
			g.Go(func() error {
				sp, err := h.resolveScope(gCtx, snap, subject, sc.ScopeType, sc.ScopeId)
				if err != nil {
					h.logger.Warn("failed to resolve scope, skipping", "subject", subject, "scope_type", sc.ScopeType, "scope_id", sc.ScopeId, "error", err)
					return nil
				}
				results[i].sp = sp
				return nil
			})
		}
		_ = g.Wait()

		for _, sr := range results {
			if sr.sp != nil {
				h.attachScope(&resp, sr.scopeType, sr.scopeID, sr.sp)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("Vary", "Authorization, Cookie")
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveScope fetches the user's roles for one scope and resolves permissions from the cached snapshot.
func (h *Handler) resolveScope(ctx context.Context, snap *roleSnapshot, subject, scopeType, scopeID string) (*scopedPermissions, error) {
	rolesResp, err := h.authzClient.client.ListSubjectRoles(ctx, &pb.ListSubjectRolesRequest{
		Subject:   subject,
		ScopeType: scopeType,
		ScopeId:   scopeID,
	})
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	effectiveRoles := collectEffectiveRoles(snap, rolesResp.Roles)

	var permissions []permissionEntry
	seen := make(map[string]struct{})
	for _, roleName := range effectiveRoles {
		cr, ok := snap.roles[roleName]
		if !ok {
			continue
		}
		for _, p := range cr.Permissions {
			key := p.Action + ":" + p.Resource
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			permissions = append(permissions, p)
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
	w.Header().Set("Vary", "Authorization, Cookie")
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

// collectEffectiveRoles walks the parent hierarchy in-memory using the cached snapshot.
func collectEffectiveRoles(snap *roleSnapshot, directRoles []string) []string {
	seen := make(map[string]struct{})
	var result []string

	var walk func(roleName string)
	walk = func(roleName string) {
		if _, ok := seen[roleName]; ok {
			return
		}
		seen[roleName] = struct{}{}
		result = append(result, roleName)

		cr, ok := snap.roles[roleName]
		if !ok {
			return
		}
		for _, parent := range cr.Parents {
			walk(parent)
		}
	}

	for _, role := range directRoles {
		walk(role)
	}
	return result
}
