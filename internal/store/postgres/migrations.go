package postgres

import (
	"context"
	"fmt"
)

// migration holds a single schema migration step.
type migration struct {
	name string
	up   string
}

var migrations = []migration{
	{
		name: "001_initial",
		up: `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email        TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    avatar_url   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email));

CREATE TABLE IF NOT EXISTS oauth_accounts (
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email            TEXT NOT NULL DEFAULT '',
    display_name     TEXT NOT NULL DEFAULT '',
    avatar_url       TEXT NOT NULL DEFAULT '',
    access_token     TEXT NOT NULL DEFAULT '',
    refresh_token    TEXT NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ,
    linked_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_user_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts (user_id);
`,
	},
	{
		name: "002_sts_jti_log",
		up: `
CREATE TABLE IF NOT EXISTS sts_jti_log (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sts_jti_log_expires_at ON sts_jti_log (expires_at);
`,
	},
}

// runMigrations creates a migrations tracking table and applies pending migrations.
func (s *Store) runMigrations(ctx context.Context) error {
	// Create migrations tracking table.
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	for _, m := range migrations {
		// Check if already applied.
		var exists bool
		err := s.pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = $1)", m.name,
		).Scan(&exists)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", m.name, err)
		}
		if exists {
			continue
		}

		// Apply migration in a transaction.
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning migration %s: %w", m.name, err)
		}

		if _, err := tx.Exec(ctx, m.up); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("applying migration %s: %w", m.name, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (name) VALUES ($1)", m.name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording migration %s: %w", m.name, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %s: %w", m.name, err)
		}

		s.logger.Info("applied migration", "name", m.name)
	}

	return nil
}
