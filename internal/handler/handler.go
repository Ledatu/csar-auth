// Package handler wires HTTP routes for csar-authn.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/botverify"
	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/sts"
)

// Handler holds dependencies for HTTP handlers.
// cfg is stored behind an atomic pointer so config changes are visible to
// request handlers without restarting the service.
type Handler struct {
	store         store.Store
	sessionMgr    *session.Manager
	sessMgr       *session.SessionManager
	oauthMgr      *oauth.Manager
	stsHandler    *sts.Handler   // nil when STS is not configured
	authzClient   *AuthzClient   // nil when authz is not configured
	auditRecorder audit.Recorder // nil when audit is not configured
	logger        *slog.Logger
	cfg           atomic.Pointer[config.Config]
}

// New creates a Handler with all dependencies.
// stsHandler, authzClient, and auditRecorder may be nil when their features are not enabled.
func New(st store.Store, sessionMgr *session.Manager, sessMgr *session.SessionManager, oauthMgr *oauth.Manager, stsHandler *sts.Handler, authzClient *AuthzClient, auditRecorder audit.Recorder, logger *slog.Logger, cfg *config.Config) *Handler {
	h := &Handler{
		store:         st,
		sessionMgr:    sessionMgr,
		sessMgr:       sessMgr,
		oauthMgr:      oauthMgr,
		stsHandler:    stsHandler,
		authzClient:   authzClient,
		auditRecorder: auditRecorder,
		logger:        logger,
	}
	h.cfg.Store(cfg)
	return h
}

// SetConfig atomically replaces the active configuration.
func (h *Handler) SetConfig(cfg *config.Config) {
	h.cfg.Store(cfg)
}

// Config returns the current configuration snapshot.
func (h *Handler) Config() *config.Config {
	return h.cfg.Load()
}

// RegisterRoutes sets up all HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	cfg := h.cfg.Load()
	cookieSameSite := httpx.ParseSameSite(cfg.Cookie.SameSite)

	// OAuth login initiation: GET /auth/{provider}
	mux.Handle("GET /auth/{provider}", h.oauthMgr.BeginAuthHandler())

	// OAuth callback: GET /auth/{provider}/callback
	mux.Handle("GET /auth/{provider}/callback", oauth.CallbackHandler(
		h.store,
		h.sessionMgr,
		h.sessMgr,
		h.oauthMgr,
		cfg.Cookie.Name,
		cfg.Cookie.Domain,
		cfg.Cookie.Secure,
		cookieSameSite,
		h.logger,
	))

	// Logout: POST /auth/logout
	mux.HandleFunc("POST /auth/logout", h.handleLogout)

	// Current user info: GET /auth/me
	mux.HandleFunc("GET /auth/me", h.handleMe)

	// Current user's active sessions: GET /auth/me/sessions
	mux.HandleFunc("GET /auth/me/sessions", h.handleMeSessions)
	mux.HandleFunc("POST /auth/me/sessions/revoke-others", h.handleRevokeOtherMeSessions)
	mux.HandleFunc("POST /auth/me/sessions/{session_id}/revoke", h.handleRevokeMeSession)

	// Session validation for router subrequests: GET /auth/validate
	mux.HandleFunc("GET /auth/validate", h.handleValidate)

	// JWKS endpoint: GET /.well-known/jwks.json
	mux.Handle("GET /.well-known/jwks.json", session.JWKSHandler(h.sessionMgr))

	// Unlink a provider: DELETE /auth/providers/{provider}
	mux.HandleFunc("DELETE /auth/providers/{provider}", h.handleUnlinkProvider)

	// Account merge: initiate merge OAuth flow and execute merge.
	// Initiate lives under /auth/merge/start/{provider} to avoid conflict
	// with the wildcard in GET /auth/{provider}/callback.
	mux.HandleFunc("GET /auth/merge/start/{provider}", h.handleMergeInitiate)
	mux.HandleFunc("POST /auth/merge", h.handleMerge)

	// STS token exchange: POST /sts/token (optional).
	if h.stsHandler != nil {
		mux.Handle("POST /sts/token", h.stsHandler)
	}

	// Bot verification endpoints (optional).
	if cfg.BotVerify != nil && cfg.BotVerify.Enabled {
		bv := botverify.NewHandler(h.store, h.sessMgr, h.oauthMgr, cfg, h.logger)
		mux.HandleFunc("POST /auth/bot-verify/start", bv.HandleStart)
		mux.HandleFunc("GET /auth/bot-verify/status/{id}", bv.HandleStatus)
		mux.HandleFunc("POST /auth/bot-verify/finalize/{id}", bv.HandleFinalize)
		mux.HandleFunc("POST /svc/authn/bot-verify/confirm", bv.HandleConfirm)
	}

	// Permissions endpoints (optional, requires authz service).
	if h.authzClient != nil {
		mux.HandleFunc("GET /auth/me/permissions", h.handlePermissions)
		mux.HandleFunc("GET /auth/me/check", h.handleCheck)

		// Service account admin endpoints.
		mux.HandleFunc("GET /admin/users", h.handleListAdminUsers)
		mux.HandleFunc("GET /admin/service-accounts", h.handleListServiceAccounts)
		mux.HandleFunc("POST /admin/service-accounts", h.handleCreateServiceAccount)
		mux.HandleFunc("GET /admin/service-accounts/{name}", h.handleGetServiceAccount)
		mux.HandleFunc("DELETE /admin/service-accounts/{name}", h.handleRevokeServiceAccount)
		mux.HandleFunc("POST /admin/service-accounts/{name}/rotate", h.handleRotateServiceAccount)

		mux.HandleFunc("GET /admin/sessions", h.handleListAdminSessions)
		mux.HandleFunc("POST /admin/sessions/{session_id}/revoke", h.handleRevokeAdminSession)
	}
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()

	// Revoke directly by cookie value — no need to validate (and risk
	// extending) the session on the way out.
	if cookie, err := r.Cookie(cfg.Cookie.Name); err == nil {
		_ = h.sessMgr.Revoke(r.Context(), cookie.Value)
	}

	http.SetCookie(w, h.sessionCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	accounts, err := h.store.GetOAuthAccountsByUserID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to fetch oauth accounts", "user_id", user.ID, "error", err)
		accounts = nil
	}

	type linkedAccount struct {
		Provider       string                 `json:"provider"`
		ProviderUserID string                 `json:"provider_user_id,omitempty"`
		DisplayName    string                 `json:"display_name,omitempty"`
		Email          string                 `json:"email,omitempty"`
		EmailVerified  bool                   `json:"email_verified"`
		Metadata       map[string]interface{} `json:"metadata,omitempty"`
	}

	type meResponse struct {
		ID          string          `json:"id"`
		Email       string          `json:"email,omitempty"`
		Phone       string          `json:"phone,omitempty"`
		DisplayName string          `json:"display_name"`
		AvatarURL   string          `json:"avatar_url,omitempty"`
		Accounts    []linkedAccount `json:"linked_accounts,omitempty"`
	}

	resp := meResponse{
		ID:          user.ID.String(),
		Email:       user.Email,
		Phone:       user.Phone,
		DisplayName: user.DisplayName,
		AvatarURL:   user.AvatarURL,
	}
	for _, a := range accounts {
		resp.Accounts = append(resp.Accounts, linkedAccount{
			Provider:       a.Provider,
			ProviderUserID: a.ProviderUserID,
			DisplayName:    a.DisplayName,
			Email:          a.Email,
			EmailVerified:  a.EmailVerified,
			Metadata:       a.ProviderMetadata,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleUnlinkProvider(w http.ResponseWriter, r *http.Request) {
	_, user, ok := h.authenticateRequest(w, r)
	if !ok {
		return
	}

	provider := r.PathValue("provider")
	if provider == "" {
		http.Error(w, "missing provider", http.StatusBadRequest)
		return
	}

	count, err := h.store.CountOAuthAccounts(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to count oauth accounts", "user_id", user.ID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count <= 1 {
		http.Error(w, "cannot unlink the last provider", http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteOAuthAccount(r.Context(), provider, user.ID); err != nil {
		h.logger.Error("failed to unlink provider", "user_id", user.ID, "provider", provider, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	afterJSON, _ := json.Marshal(map[string]any{
		"provider": provider,
	})
	h.recordAudit(r, user.ID.String(), "oauth_provider.unlink", "oauth_provider", provider, afterJSON)

	h.logger.Info("provider unlinked", "user_id", user.ID, "provider", provider)
	w.WriteHeader(http.StatusNoContent)
}

// handleValidate is a lightweight session check for router subrequests.
// Returns 200 with X-User-ID, X-User-Email, and X-Gateway-Subject headers, or 401.
// Does NOT set cookies (response goes to the router, not the browser).
func (h *Handler) handleValidate(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()
	cookie, err := r.Cookie(cfg.Cookie.Name)
	if err != nil {
		http.Error(w, "missing session", http.StatusUnauthorized)
		return
	}

	sess, err := h.sessMgr.Validate(r.Context(), cookie.Value)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	user, err := h.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}
	user = h.followMerge(r, user)
	if user == nil {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-User-ID", user.ID.String())
	w.Header().Set("X-User-Email", user.Email)
	w.Header().Set(gatewayctx.HeaderSubject, user.ID.String())
	w.WriteHeader(http.StatusOK)
}
