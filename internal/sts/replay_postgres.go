package sts

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresReplayStore is a durable ReplayStore backed by PostgreSQL.
// It uses the sts_jti_log table to track seen JTI values across restarts
// and multi-instance deployments.
type PostgresReplayStore struct {
	pool   *pgxpool.Pool
	cancel context.CancelFunc
}

// NewPostgresReplayStore creates a Postgres-backed replay store.
// A background goroutine periodically removes expired entries.
func NewPostgresReplayStore(pool *pgxpool.Pool) *PostgresReplayStore {
	ctx, cancel := context.WithCancel(context.Background())
	s := &PostgresReplayStore{pool: pool, cancel: cancel}
	go s.cleanup(ctx)
	return s
}

// CheckAndRecord atomically checks if the (issuer, jti) pair exists and
// inserts it if not. Returns true if the pair was already present (replay detected).
func (s *PostgresReplayStore) CheckAndRecord(ctx context.Context, issuer, jti string, exp time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO sts_jti_log (issuer, jti, expires_at) VALUES ($1, $2, $3) ON CONFLICT (issuer, jti) DO NOTHING`,
		issuer, jti, exp,
	)
	if err != nil {
		return false, err
	}
	// If RowsAffected == 0, the row already existed (replay).
	return tag.RowsAffected() == 0, nil
}

// Stop cancels the background cleanup goroutine.
func (s *PostgresReplayStore) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *PostgresReplayStore) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = s.pool.Exec(ctx, `DELETE FROM sts_jti_log WHERE expires_at < NOW()`)
		}
	}
}
