// Package botverify implements bot-based identity verification for csar-authn.
// Users send a short code to a Telegram/VK bot on their phone, proving
// ownership of a messenger account without needing the OAuth redirect flow.
package botverify

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
)

// alphabet excludes ambiguous characters (0, O, 1, I, L).
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
const codeLength = 6

// Handler holds dependencies for bot verification endpoints.
type Handler struct {
	store    store.Store
	sessMgr  *session.SessionManager
	oauthMgr *oauth.Manager
	cfg      *config.Config
	logger   *slog.Logger
}

// NewHandler creates a Handler with all dependencies.
func NewHandler(st store.Store, sessMgr *session.SessionManager, oauthMgr *oauth.Manager, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		store:    st,
		sessMgr:  sessMgr,
		oauthMgr: oauthMgr,
		cfg:      cfg,
		logger:   logger.With("component", "botverify"),
	}
}

func generateCode() (string, error) {
	result := make([]byte, codeLength)
	max := big.NewInt(int64(len(codeAlphabet)))
	for i := range result {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = codeAlphabet[n.Int64()]
	}
	return string(result), nil
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(h[:])
}

// HandleStart initiates a bot verification flow.
// POST /auth/bot-verify/start
func (h *Handler) HandleStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bvCfg := h.cfg.BotVerify

	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = strings.SplitN(fwd, ",", 2)[0]
	}

	count, err := h.store.CountPendingBotVerifications(ctx, ip)
	if err != nil {
		h.logger.Error("counting pending verifications", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count >= bvCfg.MaxPendingPerIP {
		http.Error(w, "too many pending verifications", http.StatusTooManyRequests)
		return
	}

	intent := "login"
	var userID *uuid.UUID

	cookieName := h.cfg.Cookie.Name
	if cookie, err := r.Cookie(cookieName); err == nil {
		if sess, err := h.sessMgr.Validate(ctx, cookie.Value); err == nil {
			intent = "link"
			userID = &sess.UserID
		}
	}

	code, err := generateCode()
	if err != nil {
		h.logger.Error("generating code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	v := &store.BotVerification{
		ID:        uuid.New(),
		CodeHash:  hashCode(code),
		Intent:    intent,
		UserID:    userID,
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: now.Add(bvCfg.CodeTTL.Duration),
		UserAgent: r.UserAgent(),
		IPAddress: ip,
	}

	if err := h.store.CreateBotVerification(ctx, v); err != nil {
		h.logger.Error("creating verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type botInfo struct {
		Provider    string `json:"provider"`
		BotUsername string `json:"bot_username"`
	}
	bots := make([]botInfo, len(bvCfg.Bots))
	for i, b := range bvCfg.Bots {
		bots[i] = botInfo{Provider: b.Provider, BotUsername: b.BotUsername}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"verification_id":    v.ID.String(),
		"code":               code,
		"intent":             intent,
		"bots":               bots,
		"expires_in_seconds": int(time.Until(v.ExpiresAt).Seconds()),
	})
}

// HandleStatus is a read-only status poll.
// GET /auth/bot-verify/status/{id}
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid verification id", http.StatusBadRequest)
		return
	}

	v, err := h.store.GetBotVerification(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.logger.Error("getting verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	status := v.Status
	if (status == "pending" || status == "confirmed") && time.Now().After(v.ExpiresAt) {
		status = "expired"
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": status})
}

// HandleConfirm is the service-facing endpoint called by csar-botverify.
// POST /svc/authn/bot-verify/confirm
func (h *Handler) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	identity, ok := gatewayctx.FromContext(r.Context())
	if !ok || identity.Subject != "svc:csar-botverify" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		Code           string `json:"code"`
		Provider       string `json:"provider"`
		ProviderUserID string `json:"provider_user_id"`
		DisplayName    string `json:"display_name"`
	}
	if err := httpx.ReadJSON(r, &req); err != nil {
		httpx.WriteError(w, err)
		return
	}

	if req.Code == "" || req.Provider == "" || req.ProviderUserID == "" {
		http.Error(w, "code, provider, and provider_user_id are required", http.StatusBadRequest)
		return
	}

	if !h.isAllowedProvider(req.Provider) {
		http.Error(w, "provider not allowed", http.StatusBadRequest)
		return
	}

	ch := hashCode(req.Code)
	if err := h.store.ConfirmBotVerification(r.Context(), ch, req.Provider, req.ProviderUserID, req.DisplayName); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "code not found or expired", http.StatusNotFound)
			return
		}
		h.logger.Error("confirming verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("bot verification confirmed",
		"provider", req.Provider,
		"provider_user_id", req.ProviderUserID,
	)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) isAllowedProvider(provider string) bool {
	for _, p := range h.cfg.BotVerify.AllowedProviders {
		if p == provider {
			return true
		}
	}
	return false
}
