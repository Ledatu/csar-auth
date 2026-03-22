package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

// ErrSessionExpired is returned when a session is revoked or past its deadline.
var ErrSessionExpired = errors.New("session expired")

// SessionStore is the subset of store.Store used by SessionManager.
type SessionStore interface {
	CreateSession(ctx context.Context, s *store.Session) error
	GetSession(ctx context.Context, sessionID string) (*store.Session, error)
	TouchSession(ctx context.Context, sessionID string, now time.Time, newExpiresAt time.Time) error
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeUserSessions(ctx context.Context, userID uuid.UUID) error
}

// SessionManager manages server-side sessions with sliding-window expiry.
type SessionManager struct {
	store          SessionStore
	logger         *slog.Logger
	maxAge         time.Duration
	idleTimeout    time.Duration
	touchThreshold time.Duration
}

// NewSessionManager creates a SessionManager.
func NewSessionManager(st SessionStore, logger *slog.Logger, maxAge, idleTimeout, touchThreshold time.Duration) *SessionManager {
	return &SessionManager{
		store:          st,
		logger:         logger,
		maxAge:         maxAge,
		idleTimeout:    idleTimeout,
		touchThreshold: touchThreshold,
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create inserts a new session and returns it.
func (sm *SessionManager) Create(ctx context.Context, userID uuid.UUID, userAgent, ip string) (*store.Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sess := &store.Session{
		ID:         id,
		UserID:     userID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(sm.idleTimeout),
		UserAgent:  userAgent,
		IPAddress:  ip,
	}
	if absExpiry := now.Add(sm.maxAge); sess.ExpiresAt.After(absExpiry) {
		sess.ExpiresAt = absExpiry
	}
	if err := sm.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// Validate checks that a session is alive and optionally extends it.
func (sm *SessionManager) Validate(ctx context.Context, sessionID string) (*store.Session, error) {
	sess, err := sm.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if sess.RevokedAt != nil || now.After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	if now.After(sess.CreatedAt.Add(sm.maxAge)) {
		return nil, ErrSessionExpired
	}

	if now.Sub(sess.LastSeenAt) > sm.touchThreshold {
		newExpiry := now.Add(sm.idleTimeout)
		if absExpiry := sess.CreatedAt.Add(sm.maxAge); newExpiry.After(absExpiry) {
			newExpiry = absExpiry
		}
		if err := sm.store.TouchSession(ctx, sess.ID, now, newExpiry); err != nil {
			sm.logger.Warn("failed to touch session, keeping old expiry",
				"session_id", sess.ID, "error", err)
		} else {
			sess.LastSeenAt = now
			sess.ExpiresAt = newExpiry
		}
	}
	return sess, nil
}

// Revoke marks a single session as revoked.
func (sm *SessionManager) Revoke(ctx context.Context, sessionID string) error {
	return sm.store.RevokeSession(ctx, sessionID)
}

// RevokeAll revokes every session for a user.
func (sm *SessionManager) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	return sm.store.RevokeUserSessions(ctx, userID)
}

// CookieMaxAge returns the number of seconds the browser cookie should live.
// It is the lesser of (absolute time remaining) and (idle_timeout).
func (sm *SessionManager) CookieMaxAge(s *store.Session) int {
	absRemaining := time.Until(s.CreatedAt.Add(sm.maxAge))
	idle := sm.idleTimeout
	if absRemaining < idle {
		idle = absRemaining
	}
	if idle <= 0 {
		return 0
	}
	return int(idle.Seconds())
}
