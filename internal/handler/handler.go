// Package handler wires HTTP routes for csar-authn.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/Ledatu/csar-authn/internal/config"
	"github.com/Ledatu/csar-authn/internal/oauth"
	"github.com/Ledatu/csar-authn/internal/session"
	"github.com/Ledatu/csar-authn/internal/store"
	"github.com/Ledatu/csar-authn/internal/sts"
)

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	store      store.Store
	sessionMgr *session.Manager
	oauthMgr   *oauth.Manager
	stsHandler *sts.Handler // nil when STS is not configured
	logger     *slog.Logger
	cfg        *config.Config
}

// New creates a Handler with all dependencies.
// stsHandler may be nil when STS is not enabled.
func New(st store.Store, sessionMgr *session.Manager, oauthMgr *oauth.Manager, stsHandler *sts.Handler, logger *slog.Logger, cfg *config.Config) *Handler {
	return &Handler{
		store:      st,
		sessionMgr: sessionMgr,
		oauthMgr:   oauthMgr,
		stsHandler: stsHandler,
		logger:     logger,
		cfg:        cfg,
	}
}

// RegisterRoutes sets up all HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	cookieSameSite := parseSameSite(h.cfg.Cookie.SameSite)

	// OAuth login initiation: GET /auth/{provider}
	mux.Handle("GET /auth/{provider}", h.oauthMgr.BeginAuthHandler())

	// OAuth callback: GET /auth/{provider}/callback
	mux.Handle("GET /auth/{provider}/callback", oauth.CallbackHandler(
		h.store,
		h.sessionMgr,
		h.oauthMgr,
		h.cfg.Cookie.Name,
		h.cfg.Cookie.Secure,
		cookieSameSite,
		h.logger,
	))

	// Logout: POST /auth/logout
	mux.HandleFunc("POST /auth/logout", h.handleLogout)

	// Current user info: GET /auth/me
	mux.HandleFunc("GET /auth/me", h.handleMe)

	// JWKS endpoint: GET /.well-known/jwks.json
	mux.Handle("GET /.well-known/jwks.json", session.JWKSHandler(h.sessionMgr))

	// Health check: GET /health
	mux.HandleFunc("GET /health", h.handleHealth)

	// STS token exchange: POST /sts/token (optional).
	if h.stsHandler != nil {
		mux.Handle("POST /sts/token", h.stsHandler)
	}
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.Cookie.Name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: parseSameSite(h.cfg.Cookie.SameSite),
		MaxAge:   -1, // delete immediately
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cfg.Cookie.Name)
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
		Provider    string `json:"provider"`
		DisplayName string `json:"display_name,omitempty"`
		Email       string `json:"email,omitempty"`
	}

	type meResponse struct {
		ID          string          `json:"id"`
		Email       string          `json:"email"`
		DisplayName string          `json:"display_name"`
		AvatarURL   string          `json:"avatar_url,omitempty"`
		Accounts    []linkedAccount `json:"linked_accounts,omitempty"`
	}

	resp := meResponse{
		ID:          user.ID.String(),
		Email:       user.Email,
		DisplayName: user.DisplayName,
		AvatarURL:   user.AvatarURL,
	}
	for _, a := range accounts {
		resp.Accounts = append(resp.Accounts, linkedAccount{
			Provider:    a.Provider,
			DisplayName: a.DisplayName,
			Email:       a.Email,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
