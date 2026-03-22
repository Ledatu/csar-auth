package handler

import (
	"context"
	"sync"
	"time"

	"github.com/ledatu/csar-authn/internal/session"
)

const tokenRefreshBuffer = 30 * time.Second

// ServiceTokenSource implements grpc credentials.PerRPCCredentials by
// self-minting short-lived JWTs via session.Manager.IssueScopedToken.
// Tokens are cached and refreshed automatically before expiry.
type ServiceTokenSource struct {
	mu       sync.Mutex
	mgr      *session.Manager
	subject  string
	audience []string
	ttl      time.Duration
	token    string
	expiry   time.Time
}

// NewServiceTokenSource creates a PerRPCCredentials that mints JWTs for the
// given service identity. The token is cached for (ttl - 30s).
func NewServiceTokenSource(mgr *session.Manager, subject string, audience []string, ttl time.Duration) *ServiceTokenSource {
	return &ServiceTokenSource{
		mgr:      mgr,
		subject:  subject,
		audience: audience,
		ttl:      ttl,
	}
}

// GetRequestMetadata returns an authorization Bearer header with a cached
// or freshly minted JWT.
func (s *ServiceTokenSource) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	tok, err := s.cachedToken()
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

// RequireTransportSecurity returns true — service tokens must only be
// sent over TLS-protected connections.
func (s *ServiceTokenSource) RequireTransportSecurity() bool { return true }

func (s *ServiceTokenSource) cachedToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expiry) {
		return s.token, nil
	}

	tok, err := s.mgr.IssueScopedToken(s.subject, s.audience, s.ttl)
	if err != nil {
		return "", err
	}
	s.token = tok
	s.expiry = time.Now().Add(s.ttl - tokenRefreshBuffer)
	return tok, nil
}
