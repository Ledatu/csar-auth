package postgres

import (
	"context"

	"github.com/ledatu/csar-core/pgutil"
)

var migrations = []pgutil.Migration{
	{
		Name: "001_initial",
		Up: `
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
		Name: "002_sts_jti_log",
		Up: `
CREATE TABLE IF NOT EXISTS sts_jti_log (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sts_jti_log_expires_at ON sts_jti_log (expires_at);
`,
	},
	{
		Name: "003_sts_jti_log_add_issuer",
		Up: `
ALTER TABLE sts_jti_log ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE sts_jti_log DROP CONSTRAINT IF EXISTS sts_jti_log_pkey;
ALTER TABLE sts_jti_log ADD PRIMARY KEY (issuer, jti);
`,
	},
	{
		Name: "004_account_linking",
		Up: `
ALTER TABLE oauth_accounts ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
`,
	},
	{
		Name: "005_telegram_support",
		Up: `
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
DROP INDEX IF EXISTS idx_users_email_lower;
CREATE UNIQUE INDEX idx_users_email_lower ON users (lower(email)) WHERE email IS NOT NULL AND email != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users (phone) WHERE phone IS NOT NULL AND phone != '';
`,
	},
	{
		Name: "006_service_accounts",
		Up: `
CREATE TABLE IF NOT EXISTS service_accounts (
    name                TEXT PRIMARY KEY,
    public_key_pem      TEXT NOT NULL,
    allowed_audiences   TEXT[] NOT NULL DEFAULT '{}',
    allow_all_audiences BOOLEAN NOT NULL DEFAULT false,
    token_ttl           INTERVAL NOT NULL DEFAULT '1 hour',
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'revoked')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);
`,
	},
	{
		Name: "007_sessions",
		Up: `
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    user_agent   TEXT NOT NULL DEFAULT '',
    ip_address   TEXT NOT NULL DEFAULT '',
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at) WHERE revoked_at IS NULL;
`,
	},
	{
		Name: "008_account_merge",
		Up: `
ALTER TABLE users ADD COLUMN IF NOT EXISTS merged_into UUID REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS merged_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS merge_records (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash         TEXT NOT NULL UNIQUE,
    source_user        UUID NOT NULL REFERENCES users(id),
    target_user        UUID NOT NULL REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    consumed_at        TIMESTAMPTZ,
    authz_completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_merge_records_pending
    ON merge_records (consumed_at) WHERE authz_completed_at IS NULL;
`,
	},
}

// runMigrations applies pending schema migrations using the shared runner.
func (s *Store) runMigrations(ctx context.Context) error {
	return pgutil.RunMigrations(ctx, s.pool, "schema_migrations", migrations, s.logger)
}
