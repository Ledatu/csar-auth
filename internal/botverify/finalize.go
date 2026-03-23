package botverify

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/store"
)

// HandleFinalize consumes a confirmed verification and performs side effects:
// login (FindOrCreateUser + session) or link (LinkOAuthAccount + merge path).
// POST /auth/bot-verify/finalize/{id}
func (h *Handler) HandleFinalize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid verification id", http.StatusBadRequest)
		return
	}

	v, err := h.store.ConsumeBotVerification(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "verification not confirmed, expired, or already consumed", http.StatusConflict)
			return
		}
		h.logger.Error("consuming verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	acct := &store.OAuthAccount{
		Provider:       v.Provider,
		ProviderUserID: v.ProviderUserID,
		DisplayName:    v.ProviderDisplay,
	}

	switch v.Intent {
	case "login":
		h.finalizeLogin(w, r, v, acct)
	case "link":
		h.finalizeLink(w, r, v, acct)
	default:
		h.logger.Error("unknown verification intent", "intent", v.Intent)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) finalizeLogin(w http.ResponseWriter, r *http.Request, v *store.BotVerification, acct *store.OAuthAccount) {
	ctx := r.Context()

	user, result, err := h.store.FindOrCreateUser(ctx, acct, "", "", v.ProviderDisplay, "")
	if err != nil {
		h.logger.Error("find or create user", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch result {
	case store.ResultCreatedNewUser:
		h.logger.Info("new user created via bot verification", "user_id", user.ID)
	case store.ResultLinkedToExisting:
		h.logger.Info("auto-linked via bot verification", "user_id", user.ID, "provider", v.Provider)
	default:
		h.logger.Info("existing user authenticated via bot verification", "user_id", user.ID)
	}

	sess, err := h.sessMgr.Create(ctx, user.ID, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		h.logger.Error("session creation failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.Cookie.Name,
		Value:    sess.ID,
		Path:     "/",
		Domain:   h.cfg.Cookie.Domain,
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(h.cfg.Cookie.SameSite),
		MaxAge:   h.sessMgr.CookieMaxAge(sess),
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"result":  "authenticated",
		"user_id": user.ID.String(),
	})
}

func (h *Handler) finalizeLink(w http.ResponseWriter, r *http.Request, v *store.BotVerification, acct *store.OAuthAccount) {
	ctx := r.Context()

	cookie, err := r.Cookie(h.cfg.Cookie.Name)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	sess, err := h.sessMgr.Validate(ctx, cookie.Value)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	if v.UserID == nil || *v.UserID != sess.UserID {
		http.Error(w, "session user does not match verification", http.StatusForbidden)
		return
	}

	userID := sess.UserID
	if err := h.store.LinkOAuthAccount(ctx, userID, acct); err != nil {
		if errors.Is(err, store.ErrProviderAlreadyLinked) {
			h.handleBotMerge(w, r, v, userID)
			return
		}
		h.logger.Error("linking account", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("provider linked via bot verification",
		"user_id", userID, "provider", v.Provider,
	)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"result":   "linked",
		"provider": v.Provider,
	})
}

// handleBotMerge creates a merge record when the bot-verified identity already
// belongs to a different user, reusing the existing merge_records infrastructure.
func (h *Handler) handleBotMerge(w http.ResponseWriter, r *http.Request, v *store.BotVerification, targetID uuid.UUID) {
	ctx := r.Context()

	existingAcct, err := h.store.GetOAuthAccount(ctx, v.Provider, v.ProviderUserID)
	if err != nil {
		h.logger.Error("looking up existing owner for merge", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sourceID := existingAcct.UserID
	if sourceID == targetID {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"result":   "linked",
			"provider": v.Provider,
		})
		return
	}

	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		h.logger.Error("generating merge token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tokenStr := hex.EncodeToString(rawToken)
	hash := sha256.Sum256([]byte(tokenStr))
	tokenHash := hex.EncodeToString(hash[:])

	rec := &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  tokenHash,
		SourceUser: sourceID,
		TargetUser: targetID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	if err := h.store.CreateMergeRecord(ctx, rec); err != nil {
		h.logger.Error("creating merge record", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "csar_merge",
		Value:    tokenStr,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   h.cfg.Cookie.Secure,
		SameSite: httpx.ParseSameSite(h.cfg.Cookie.SameSite),
	})

	h.logger.Info("bot-merge record created",
		"source_user", sourceID, "target_user", targetID, "provider", v.Provider,
	)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"result":      "merge_available",
		"source_user": sourceID.String(),
		"merge_ready": true,
	})
}
