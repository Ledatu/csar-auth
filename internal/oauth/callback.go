package oauth

import (
	"errors"
	"log/slog"
	"net/http"

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

		intent, _ := gothic.GetFromSession("intent", r)

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

		var phone string
		if pn, ok := gothUser.RawData["phone_number"]; ok {
			if s, ok := pn.(string); ok {
				phone = s
			}
		}

		if intent == "link" {
			handleLinkCallback(w, r, st, sessMgr, oauthMgr, cookieName, acct, phone, provider, logger)
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
			logger.Warn("provider account already linked to another user",
				"provider", provider,
				"provider_user_id", acct.ProviderUserID,
			)
			redirectURL := httpx.AppendQuery(frontendURL, "error", "already_linked", "provider", provider)
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
