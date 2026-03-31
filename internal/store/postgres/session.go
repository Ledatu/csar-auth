package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
)

func (s *Store) CreateSession(ctx context.Context, sess *store.Session) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, created_at, last_seen_at, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sess.ID, sess.UserID, sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt, sess.UserAgent, sess.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *Store) GetSession(ctx context.Context, sessionID string) (*store.Session, error) {
	sess := &store.Session{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, created_at, last_seen_at, expires_at, user_agent, ip_address, revoked_at
		 FROM sessions WHERE id = $1`, sessionID,
	).Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.UserAgent, &sess.IPAddress, &sess.RevokedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return sess, nil
}

func (s *Store) TouchSession(ctx context.Context, sessionID string, now time.Time, newExpiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET last_seen_at = $2, expires_at = $3 WHERE id = $1`,
		sessionID, now, newExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (s *Store) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *Store) RevokeAdminSession(ctx context.Context, adminSessionID string) (*store.AdminSessionRow, error) {
	row := &store.AdminSessionRow{}
	err := s.pool.QueryRow(ctx,
		`UPDATE sessions s
		 SET revoked_at = now()
		 FROM users u
		 WHERE s.user_id = u.id
		   AND encode(substr(digest(s.id, 'sha256'), 1, 8), 'hex') = $1
		   AND s.revoked_at IS NULL
		   AND s.expires_at > now()
		 RETURNING s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.user_agent, s.ip_address, s.revoked_at, COALESCE(u.email, '')`,
		adminSessionID,
	).Scan(
		&row.ID, &row.UserID, &row.CreatedAt, &row.LastSeenAt, &row.ExpiresAt,
		&row.UserAgent, &row.IPAddress, &row.RevokedAt, &row.UserEmail,
	)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("revoke admin session: %w", err)
	}
	return row, nil
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE expires_at < now() OR revoked_at IS NOT NULL`,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]store.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, created_at, last_seen_at, expires_at, user_agent, ip_address, revoked_at
		 FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY last_seen_at DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list user sessions: %w", err)
	}
	defer rows.Close()

	var sessions []store.Session
	for rows.Next() {
		var sess store.Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.UserAgent, &sess.IPAddress, &sess.RevokedAt); err != nil {
			return nil, fmt.Errorf("scanning session: %w", err)
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

func (s *Store) ListAdminSessions(ctx context.Context, params store.AdminSessionListParams) ([]store.AdminSessionRow, bool, error) {
	var b strings.Builder
	args := make([]interface{}, 0, 4)
	n := 1
	b.WriteString(`
SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.user_agent, s.ip_address, s.revoked_at,
       COALESCE(u.email, '') AS user_email
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE 1=1`)
	if params.UserID != nil {
		fmt.Fprintf(&b, " AND s.user_id = $%d", n)
		args = append(args, *params.UserID)
		n++
	}
	if params.Email != "" {
		fmt.Fprintf(&b, " AND u.email ILIKE $%d", n)
		args = append(args, "%"+params.Email+"%")
		n++
	}
	switch params.Status {
	case "", "all":
	case "active":
		b.WriteString(" AND s.revoked_at IS NULL AND s.expires_at > now()")
	case "revoked":
		b.WriteString(" AND s.revoked_at IS NOT NULL")
	case "expired":
		b.WriteString(" AND s.revoked_at IS NULL AND s.expires_at <= now()")
	}
	fmt.Fprintf(&b, " ORDER BY s.last_seen_at DESC LIMIT $%d OFFSET $%d", n, n+1)
	args = append(args, params.Limit+1, params.Offset)

	rows, err := s.pool.Query(ctx, b.String(), args...)
	if err != nil {
		return nil, false, fmt.Errorf("list admin sessions: %w", err)
	}
	defer rows.Close()

	var out []store.AdminSessionRow
	for rows.Next() {
		var row store.AdminSessionRow
		if err := rows.Scan(
			&row.ID, &row.UserID, &row.CreatedAt, &row.LastSeenAt, &row.ExpiresAt,
			&row.UserAgent, &row.IPAddress, &row.RevokedAt, &row.UserEmail,
		); err != nil {
			return nil, false, fmt.Errorf("scanning admin session: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(out) > params.Limit
	if hasMore {
		out = out[:params.Limit]
	}
	return out, hasMore, nil
}
