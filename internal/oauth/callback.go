package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/markbates/goth/gothic"

	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
)

// CallbackHandler returns an http.Handler that completes the OAuth flow.
// It handles two intents:
//   - "login" (default): lookup-or-create user, create server-side session
//   - "link": link the provider to an already-authenticated user
func CallbackHandler(
	st store.Store,
	jwtMgr *session.Manager,
	sessMgr *session.SessionManager,
	oauthMgr *Manager,
	cookieName string,
	cookieDomain string,
	cookieSecure bool,
	cookieSameSite http.SameSite,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := extractProvider(r)
		if provider == "" {
			http.Error(w, "missing provider", http.StatusBadRequest)
			return
		}
		q := r.URL.Query()
		q.Set("provider", provider)
		r.URL.RawQuery = q.Encode()

		// Read intent from dedicated cookie (bypasses fragile Goth session).
		var intent string
		if c, err := r.Cookie("csar_intent"); err == nil {
			intent = c.Value
		}
		// Clear the intent cookie immediately.
		http.SetCookie(w, &http.Cookie{
			Name:     "csar_intent",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: cookieSameSite,
		})

		logger.Info("callback intent resolved", "intent", intent, "provider", provider)

		gothUser, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			logger.Error("oauth callback failed", "provider", provider, "error", err)
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}

		logger.Info("oauth callback received",
			"provider", gothUser.Provider,
			"provider_user_id", gothUser.UserID,
			"email", gothUser.Email,
		)

		emailVerified := ExtractEmailVerified(gothUser, oauthMgr.IsTrusted(provider))

		acct := &store.OAuthAccount{
			Provider:       gothUser.Provider,
			ProviderUserID: gothUser.UserID,
			Email:          gothUser.Email,
			DisplayName:    gothUser.Name,
			AvatarURL:      gothUser.AvatarURL,
			AccessToken:    gothUser.AccessToken,
			RefreshToken:   gothUser.RefreshToken,
			EmailVerified:  emailVerified,
		}
		if !gothUser.ExpiresAt.IsZero() {
			t := gothUser.ExpiresAt
			acct.ExpiresAt = &t
		}

		phone := extractPhone(gothUser.RawData)

		if gothUser.Provider == "telegram" {
			botID := extractTelegramBotID(gothUser.RawData)
			logger.Info("telegram ID resolution check",
				"oidc_sub", gothUser.UserID,
				"bot_id", botID,
				"raw_data_keys", rawDataKeys(gothUser.RawData))
			if botID != "" && botID != gothUser.UserID {
				oidcSub := gothUser.UserID
				tgMeta := map[string]interface{}{"oidc_sub": oidcSub}

				acct.ProviderUserID = botID
				acct.ProviderMetadata = tgMeta

				migrated, err := st.MigrateTelegramID(r.Context(), oidcSub, botID, tgMeta)
				if err != nil {
					logger.Warn("telegram ID migration failed",
						"oidc_sub", oidcSub, "bot_id", botID, "error", err)
				} else if migrated {
					logger.Info("migrated telegram provider_user_id to bot API ID",
						"from_oidc_sub", oidcSub, "to_bot_id", botID)
				}
			}
		}

		if intent == "link" {
			handleLinkCallback(w, r, st, sessMgr, oauthMgr, cookieName, acct, phone, provider, logger)
			return
		}

		if intent == "merge" {
			handleMergeCallback(w, r, st, sessMgr, oauthMgr, cookieName, cookieSecure, cookieSameSite, acct, provider, logger)
			return
		}

		handleLoginCallback(w, r, st, sessMgr, oauthMgr, cookieName, cookieDomain, cookieSecure, cookieSameSite, acct, gothUser.Email, phone, gothUser.Name, gothUser.AvatarURL, provider, logger)
	})
}

func handleLoginCallback(
	w http.ResponseWriter, r *http.Request,
	st store.Store,
	sessMgr *session.SessionManager,
	oauthMgr *Manager,
	cookieName string,
	cookieDomain string,
	cookieSecure bool,
	cookieSameSite http.SameSite,
	acct *store.OAuthAccount,
	email, phone, displayName, avatarURL, provider string,
	logger *slog.Logger,
) {
	frontendURL := oauthMgr.FrontendURL()
	if frontendURL == "" {
		frontendURL = "/"
	}

	user, result, err := st.FindOrCreateUser(r.Context(), acct, email, phone, displayName, avatarURL)
	if err != nil {
		if errors.Is(err, store.ErrUnverifiedEmailConflict) {
			logger.Warn("unverified email conflicts with existing user",
				"provider", provider,
				"email", email,
			)
			redirectURL := httpx.AppendQuery(frontendURL, "error", "email_conflict", "provider", provider)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}
		logger.Error("find or create user failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch result {
	case store.ResultCreatedNewUser:
		logger.Info("new user created", "user_id", user.ID, "email", user.Email)
	case store.ResultLinkedToExisting:
		logger.Info("auto-linked provider to existing user", "user_id", user.ID, "provider", provider)
	default:
		logger.Info("existing user authenticated", "user_id", user.ID, "email", user.Email)
	}

	sess, err := sessMgr.Create(r.Context(), user.ID, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		logger.Error("session creation failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    sess.ID,
		Path:     "/",
		Domain:   cookieDomain,
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: cookieSameSite,
		MaxAge:   sessMgr.CookieMaxAge(sess),
	})

	http.Redirect(w, r, frontendURL, http.StatusTemporaryRedirect)
}

// handleLinkCallback handles the explicit account linking flow.
// The user must already be authenticated (have a valid session cookie).
func handleLinkCallback(
	w http.ResponseWriter, r *http.Request,
	st store.Store,
	sessMgr *session.SessionManager,
	oauthMgr *Manager,
	cookieName string,
	acct *store.OAuthAccount,
	phone, provider string,
	logger *slog.Logger,
) {
	frontendURL := oauthMgr.FrontendURL()
	if frontendURL == "" {
		frontendURL = "/"
	}

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		logger.Warn("link callback without session cookie", "provider", provider)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "not_authenticated")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	sess, err := sessMgr.Validate(r.Context(), cookie.Value)
	if err != nil {
		logger.Warn("link callback with invalid session", "provider", provider, "error", err)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "invalid_session")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	userID := sess.UserID

	if err := st.LinkOAuthAccount(r.Context(), userID, acct); err != nil {
		if errors.Is(err, store.ErrProviderAlreadyLinked) {
			logger.Warn("provider account already linked to another user — merge available",
				"provider", provider,
				"provider_user_id", acct.ProviderUserID,
			)
			redirectURL := httpx.AppendQuery(frontendURL, "merge_available", provider)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}
		logger.Error("link oauth account failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if phone != "" {
		user, err := st.GetUserByID(r.Context(), userID)
		if err == nil && user.Phone == "" {
			user.Phone = phone
			if err := st.UpdateUser(r.Context(), user); err != nil {
				logger.Warn("failed to update user phone on link", "user_id", userID, "error", err)
			}
		}
	}

	logger.Info("provider linked to user", "user_id", userID, "provider", provider)
	redirectURL := httpx.AppendQuery(frontendURL, "linked", provider)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// handleMergeCallback handles the OAuth callback for intent=merge.
// It verifies the OAuth identity belongs to a different user (source),
// validates the session cookie matches the merge target, creates a
// merge record, and sets an HttpOnly cookie with the merge token.
func handleMergeCallback(
	w http.ResponseWriter, r *http.Request,
	st store.Store,
	sessMgr *session.SessionManager,
	oauthMgr *Manager,
	cookieName string,
	cookieSecure bool,
	cookieSameSite http.SameSite,
	acct *store.OAuthAccount,
	provider string,
	logger *slog.Logger,
) {
	frontendURL := oauthMgr.FrontendURL()
	if frontendURL == "" {
		frontendURL = "/"
	}

	// Read merge_target from dedicated cookie (replaces Goth session).
	var mergeTarget string
	if c, err := r.Cookie("csar_merge_target"); err == nil {
		mergeTarget = c.Value
	}
	// Clear the merge_target cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "csar_merge_target",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: cookieSameSite,
	})

	if mergeTarget == "" {
		logger.Warn("merge callback missing merge_target cookie", "provider", provider)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "merge_state_missing")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	// Validate session cookie — must prove ownership of target user.
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		logger.Warn("merge callback without session cookie", "provider", provider)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "not_authenticated")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	sess, err := sessMgr.Validate(r.Context(), cookie.Value)
	if err != nil {
		logger.Warn("merge callback with invalid session", "provider", provider, "error", err)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "invalid_session")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	targetID := sess.UserID

	// Anti-confusion: session user must match merge_target from Goth session.
	if targetID.String() != mergeTarget {
		logger.Warn("merge target mismatch",
			"session_user", targetID, "merge_target", mergeTarget,
		)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "merge_target_mismatch")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	// Look up which user owns this OAuth identity (the source).
	existingAcct, err := st.GetOAuthAccount(r.Context(), acct.Provider, acct.ProviderUserID)
	if err != nil {
		logger.Error("merge callback: cannot find source OAuth account", "error", err)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "merge_source_not_found")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	sourceID := existingAcct.UserID
	if sourceID == targetID {
		logger.Warn("merge callback: source equals target", "user_id", targetID)
		redirectURL := httpx.AppendQuery(frontendURL, "error", "merge_self")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	// Generate a random token; store only its hash.
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		logger.Error("failed to generate merge token", "error", err)
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
	if err := st.CreateMergeRecord(r.Context(), rec); err != nil {
		logger.Error("failed to create merge record", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set HttpOnly cookie with the raw token.
	http.SetCookie(w, &http.Cookie{
		Name:     "csar_merge",
		Value:    tokenStr,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: cookieSameSite,
	})

	logger.Info("merge record created",
		"source_user", sourceID, "target_user", targetID, "provider", provider,
	)
	redirectURL := httpx.AppendQuery(frontendURL, "merge_ready", "true")
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// extractPhone tries to pull a phone number from provider-specific RawData.
// Supports:
//   - OIDC "phone_number" (Telegram)
//   - Yandex "default_phone": {"number": "+7..."}
func extractPhone(raw map[string]interface{}) string {
	// OIDC standard claim (Telegram, Google, etc.)
	if pn, ok := raw["phone_number"]; ok {
		if s, ok := pn.(string); ok && s != "" {
			return s
		}
	}

	// Yandex: default_phone is an object with a "number" field
	if dp, ok := raw["default_phone"]; ok {
		if m, ok := dp.(map[string]interface{}); ok {
			if n, ok := m["number"]; ok {
				if s, ok := n.(string); ok && s != "" {
					return s
				}
			}
		}
	}

	return ""
}

func rawDataKeys(raw map[string]interface{}) []string {
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractTelegramBotID extracts the numeric Telegram Bot API user ID from the
// OIDC id_token claims. Telegram's id_token includes both "sub" (OIDC subject)
// and "id" (Bot API user ID); we use the latter to match legacy records.
func extractTelegramBotID(raw map[string]interface{}) string {
	v, ok := raw["id"]
	if !ok {
		return ""
	}
	switch id := v.(type) {
	case float64:
		return strconv.FormatInt(int64(id), 10)
	case json.Number:
		return id.String()
	}
	return ""
}
