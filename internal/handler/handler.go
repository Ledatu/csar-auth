// Package handler wires HTTP routes for csar-authn.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/httpx"

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
	store       store.Store
	sessionMgr  *session.Manager
	oauthMgr    *oauth.Manager
	stsHandler  *sts.Handler // nil when STS is not configured
	authzClient *AuthzClient // nil when authz is not configured
	auditStore  audit.Store  // nil when audit is not configured
	logger      *slog.Logger
	cfg         atomic.Pointer[config.Config]
}

// New creates a Handler with all dependencies.
// stsHandler, authzClient, and auditStore may be nil when their features are not enabled.
func New(st store.Store, sessionMgr *session.Manager, oauthMgr *oauth.Manager, stsHandler *sts.Handler, authzClient *AuthzClient, auditStore audit.Store, logger *slog.Logger, cfg *config.Config) *Handler {
	h := &Handler{
		store:       st,
		sessionMgr:  sessionMgr,
		oauthMgr:    oauthMgr,
		stsHandler:  stsHandler,
		authzClient: authzClient,
		auditStore:  auditStore,
		logger:      logger,
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
		h.oauthMgr,
		cfg.Cookie.Name,
		cfg.Cookie.Secure,
		cookieSameSite,
		h.logger,
	))

	// Logout: POST /auth/logout
	mux.HandleFunc("POST /auth/logout", h.handleLogout)

	// Current user info: GET /auth/me
	mux.HandleFunc("GET /auth/me", h.handleMe)

	// JWKS endpoint: GET /.well-known/jwks.json
	mux.Handle("GET /.well-known/jwks.json", session.JWKSHandler(h.sessionMgr))

	// Unlink a provider: DELETE /auth/providers/{provider}
	mux.HandleFunc("DELETE /auth/providers/{provider}", h.handleUnlinkProvider)

	// STS token exchange: POST /sts/token (optional).
	if h.stsHandler != nil {
		mux.Handle("POST /sts/token", h.stsHandler)
	}

	// Permissions endpoints (optional, requires authz service).
	if h.authzClient != nil {
		mux.HandleFunc("GET /auth/me/permissions", h.handlePermissions)
		mux.HandleFunc("GET /auth/me/check", h.handleCheck)

		// Service account admin endpoints.
		mux.HandleFunc("GET /admin/service-accounts", h.handleListServiceAccounts)
		mux.HandleFunc("POST /admin/service-accounts", h.handleCreateServiceAccount)
		mux.HandleFunc("GET /admin/service-accounts/{name}", h.handleGetServiceAccount)
		mux.HandleFunc("DELETE /admin/service-accounts/{name}", h.handleRevokeServiceAccount)
		mux.HandleFunc("POST /admin/service-accounts/{name}/rotate", h.handleRotateServiceAccount)
	}
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(cfg.Cookie.SameSite),
		MaxAge:   -1, // delete immediately
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()
	cookie, err := r.Cookie(cfg.Cookie.Name)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	claims, err := h.sessionMgr.VerifyToken(cookie.Value)
	if err != nil {
		h.logger.Warn("invalid session token on /auth/me", "error", err)
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.Sub)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	// Fetch the full user from the store.
	user, err := h.store.GetUserByID(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to fetch user for /me", "user_id", claims.Sub, "error", err)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	// Fetch linked accounts.
	accounts, err := h.store.GetOAuthAccountsByUserID(r.Context(), user.ID)
	if err != nil {
		h.logger.Error("failed to fetch oauth accounts", "user_id", user.ID, "error", err)
		accounts = nil // non-fatal
	}

	type linkedAccount struct {
		Provider      string `json:"provider"`
		DisplayName   string `json:"display_name,omitempty"`
		Email         string `json:"email,omitempty"`
		EmailVerified bool   `json:"email_verified"`
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
			Provider:      a.Provider,
			DisplayName:   a.DisplayName,
			Email:         a.Email,
			EmailVerified: a.EmailVerified,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleUnlinkProvider(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.Load()
	cookie, err := r.Cookie(cfg.Cookie.Name)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	claims, err := h.sessionMgr.VerifyToken(cookie.Value)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	userID, err := uuid.Parse(claims.Sub)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	provider := r.PathValue("provider")
	if provider == "" {
		http.Error(w, "missing provider", http.StatusBadRequest)
		return
	}

	// Guard: cannot unlink the last provider.
	count, err := h.store.CountOAuthAccounts(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to count oauth accounts", "user_id", userID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count <= 1 {
		http.Error(w, "cannot unlink the last provider", http.StatusBadRequest)
		return
	}

	if err := h.store.DeleteOAuthAccount(r.Context(), provider, userID); err != nil {
		h.logger.Error("failed to unlink provider", "user_id", userID, "provider", provider, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("provider unlinked", "user_id", userID, "provider", provider)
	w.WriteHeader(http.StatusNoContent)
}
