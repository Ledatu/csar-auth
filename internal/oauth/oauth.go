// Package oauth handles Goth provider setup and OAuth login/callback flows.
package oauth

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/discord"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
	oidc "github.com/markbates/goth/providers/openidConnect"
	"github.com/markbates/goth/providers/vk"
	"github.com/markbates/goth/providers/yandex"

	"github.com/ledatu/csar-core/httpx"

	"github.com/ledatu/csar-authn/internal/config"
)

// Manager manages OAuth providers and the Goth session store.
// Fields guarded by mu may be swapped at runtime via Reload.
type Manager struct {
	mu               sync.RWMutex
	logger           *slog.Logger
	baseURL          string
	frontendURL      string
	trustedProviders map[string]bool
}

// NewManager initializes Goth providers from config and returns a Manager.
func NewManager(cfg *config.Config, logger *slog.Logger) (*Manager, error) {
	if err := applyGothProviders(cfg, logger); err != nil {
		return nil, err
	}

	return &Manager{
		logger:           logger,
		baseURL:          cfg.BaseURL,
		frontendURL:      cfg.FrontendURL,
		trustedProviders: buildTrustedMap(cfg),
	}, nil
}

// Reload re-initializes Goth providers and the trusted map from new config.
// On error the previous provider set remains active.
func (m *Manager) Reload(cfg *config.Config) error {
	if err := applyGothProviders(cfg, m.logger); err != nil {
		return err
	}

	trusted := buildTrustedMap(cfg)

	m.mu.Lock()
	m.trustedProviders = trusted
	m.frontendURL = cfg.FrontendURL
	m.baseURL = cfg.BaseURL
	m.mu.Unlock()
	return nil
}

// applyGothProviders sets up the Goth session store and registers all providers.
func applyGothProviders(cfg *config.Config, logger *slog.Logger) error {
	store := sessions.NewCookieStore([]byte(cfg.OAuth.SessionSecret))
	store.MaxAge(300)
	store.Options.HttpOnly = true
	store.Options.Secure = cfg.Cookie.Secure
	store.Options.SameSite = httpx.ParseSameSite(cfg.Cookie.SameSite)
	gothic.Store = store

	goth.ClearProviders()

	var providers []goth.Provider
	for _, p := range cfg.OAuth.Providers {
		callbackURL := p.CallbackURL
		if callbackURL == "" {
			callbackURL = fmt.Sprintf("%s/auth/%s/callback", cfg.BaseURL, p.Name)
		}
		provider, err := createProvider(p, callbackURL)
		if err != nil {
			return fmt.Errorf("provider %s: %w", p.Name, err)
		}
		providers = append(providers, provider)
		logger.Info("registered oauth provider", "name", p.Name, "callback", callbackURL)
	}
	goth.UseProviders(providers...)
	return nil
}

func buildTrustedMap(cfg *config.Config) map[string]bool {
	trusted := make(map[string]bool)
	for _, p := range cfg.OAuth.Providers {
		if p.Trusted {
			trusted[strings.ToLower(p.Name)] = true
		}
	}
	return trusted
}

// FrontendURL returns the configured frontend redirect target.
func (m *Manager) FrontendURL() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.frontendURL
}

// IsTrusted returns whether the provider is configured as trusted
// (i.e. always returns verified emails).
func (m *Manager) IsTrusted(provider string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.trustedProviders[strings.ToLower(provider)]
}

// BeginAuthHandler returns an http.Handler that initiates the OAuth flow.
// The provider name is extracted from the URL path: /auth/{provider}
// Accepts an optional ?intent=link query parameter for explicit account linking.
func (m *Manager) BeginAuthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := extractProvider(r)
		if provider == "" {
			http.Error(w, "missing provider", http.StatusBadRequest)
			return
		}

		// Set the provider in the query so Goth can find it.
		q := r.URL.Query()
		q.Set("provider", provider)
		r.URL.RawQuery = q.Encode()

		// Store intent (login or link) in the Goth session for retrieval in callback.
		intent := r.URL.Query().Get("intent")
		if intent == "link" {
			if err := gothic.StoreInSession("intent", "link", r, w); err != nil {
				m.logger.Error("failed to store intent in session", "error", err)
			}
		}

		gothic.BeginAuthHandler(w, r)
	})
}

func createProvider(cfg config.ProviderConfig, callbackURL string) (goth.Provider, error) {
	switch strings.ToLower(cfg.Name) {
	case "google":
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "email", "profile"}
		}
		return google.New(cfg.ClientID, cfg.ClientSecret, callbackURL, scopes...), nil

	case "github":
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"user:email"}
		}
		return github.New(cfg.ClientID, cfg.ClientSecret, callbackURL, scopes...), nil

	case "discord":
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"identify", "email"}
		}
		return discord.New(cfg.ClientID, cfg.ClientSecret, callbackURL, scopes...), nil

	case "telegram":
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "phone"}
		}
		p, err := oidc.NewNamed(
			"telegram",
			cfg.ClientID,
			cfg.ClientSecret,
			callbackURL,
			"https://oauth.telegram.org/.well-known/openid-configuration",
			scopes...,
		)
		if err != nil {
			return nil, fmt.Errorf("initializing telegram OIDC: %w", err)
		}
		p.SkipUserInfoRequest = true
		// NewNamed formats the name as "telegram-oidc"; override to match our URL routing.
		p.SetName("telegram")
		return p, nil

	case "vk":
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"email", "phone"}
		}
		return vk.New(cfg.ClientID, cfg.ClientSecret, callbackURL, scopes...), nil

	case "yandex":
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{"login:email", "login:info", "login:avatar", "login:default_phone"}
		}
		return yandex.New(cfg.ClientID, cfg.ClientSecret, callbackURL, scopes...), nil

	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Name)
	}
}

// extractProvider gets the provider name from the URL path.
// Expected path patterns: /auth/{provider} or /auth/{provider}/callback
func extractProvider(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/auth/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return parts[0]
}
