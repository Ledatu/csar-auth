// Package postgres implements the store.Store interface using PostgreSQL (pgx/v5).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ledatu/csar-auth/internal/store"
)

// Store implements store.Store backed by PostgreSQL.
type Store struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// Option configures the PostgreSQL store.
type Option func(*Store)

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Store) { s.logger = l }
}

// New creates a new PostgreSQL store and verifies the connection.
func New(ctx context.Context, dsn string, opts ...Option) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	s := &Store{
		pool:   pool,
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// Migrate runs schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	return s.runMigrations(ctx)
}

// Close releases the connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Pool returns the underlying pgxpool.Pool for shared use by other components.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// --- User operations ---

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*store.User, error) {
	u := &store.User{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, avatar_url, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*store.User, error) {
	u := &store.User{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, display_name, avatar_url, created_at, updated_at
		 FROM users WHERE lower(email) = lower($1)`, email,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

func (s *Store) CreateUser(ctx context.Context, u *store.User) (*store.User, error) {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, email, display_name, avatar_url, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		u.ID, u.Email, u.DisplayName, u.AvatarURL, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "idx_users_email_lower") {
			return nil, fmt.Errorf("user with email %q already exists: %w", u.Email, err)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

func (s *Store) UpdateUser(ctx context.Context, u *store.User) error {
	u.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET email = $2, display_name = $3, avatar_url = $4, updated_at = $5
		 WHERE id = $1`,
		u.ID, u.Email, u.DisplayName, u.AvatarURL, u.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	return nil
}

// --- OAuth account operations ---

func (s *Store) GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*store.OAuthAccount, error) {
	a := &store.OAuthAccount{}
	err := s.pool.QueryRow(ctx,
		`SELECT provider, provider_user_id, user_id, email, display_name, avatar_url,
		        access_token, refresh_token, expires_at, linked_at, updated_at
		 FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&a.Provider, &a.ProviderUserID, &a.UserID, &a.Email, &a.DisplayName, &a.AvatarURL,
		&a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.LinkedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get oauth account: %w", err)
	}
	return a, nil
}

func (s *Store) GetOAuthAccountsByUserID(ctx context.Context, userID uuid.UUID) ([]store.OAuthAccount, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT provider, provider_user_id, user_id, email, display_name, avatar_url,
		        access_token, refresh_token, expires_at, linked_at, updated_at
		 FROM oauth_accounts WHERE user_id = $1 ORDER BY linked_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list oauth accounts: %w", err)
	}
	defer rows.Close()

	var accounts []store.OAuthAccount
	for rows.Next() {
		var a store.OAuthAccount
		if err := rows.Scan(&a.Provider, &a.ProviderUserID, &a.UserID, &a.Email, &a.DisplayName, &a.AvatarURL,
			&a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.LinkedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning oauth account: %w", err)
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

func (s *Store) CreateOAuthAccount(ctx context.Context, acct *store.OAuthAccount) error {
	now := time.Now()
	acct.LinkedAt = now
	acct.UpdatedAt = now

	_, err := s.pool.Exec(ctx,
		`INSERT INTO oauth_accounts
		 (provider, provider_user_id, user_id, email, display_name, avatar_url,
		  access_token, refresh_token, expires_at, linked_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		acct.Provider, acct.ProviderUserID, acct.UserID, acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, acct.LinkedAt, acct.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("create oauth account: %w", err)
	}
	return nil
}

func (s *Store) UpdateOAuthAccount(ctx context.Context, acct *store.OAuthAccount) error {
	acct.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx,
		`UPDATE oauth_accounts
		 SET email = $3, display_name = $4, avatar_url = $5,
		     access_token = $6, refresh_token = $7, expires_at = $8, updated_at = $9
		 WHERE provider = $1 AND provider_user_id = $2`,
		acct.Provider, acct.ProviderUserID,
		acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, acct.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update oauth account: %w", err)
	}
	return nil
}

func (s *Store) DeleteOAuthAccount(ctx context.Context, provider string, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM oauth_accounts WHERE provider = $1 AND user_id = $2`,
		provider, userID,
	)
	if err != nil {
		return fmt.Errorf("delete oauth account: %w", err)
	}
	return nil
}

// FindOrCreateUser performs the lookup-or-create flow atomically:
//  1. Check oauth_accounts for (provider, provider_user_id)
//  2. If found, update tokens and return the linked user
//  3. If not found, check users by email
//  4. If user exists, create the oauth_account link
//  5. If no user, create user + oauth_account in a transaction
func (s *Store) FindOrCreateUser(ctx context.Context, acct *store.OAuthAccount, email, displayName, avatarURL string) (*store.User, bool, error) {
	// Step 1: Check if this oauth account is already linked.
	existing, err := s.GetOAuthAccount(ctx, acct.Provider, acct.ProviderUserID)
	if err == nil {
		// Already linked — update tokens and return the user.
		existing.AccessToken = acct.AccessToken
		existing.RefreshToken = acct.RefreshToken
		existing.ExpiresAt = acct.ExpiresAt
		existing.Email = acct.Email
		existing.DisplayName = acct.DisplayName
		existing.AvatarURL = acct.AvatarURL
		if err := s.UpdateOAuthAccount(ctx, existing); err != nil {
			return nil, false, fmt.Errorf("updating existing oauth account: %w", err)
		}

		user, err := s.GetUserByID(ctx, existing.UserID)
		if err != nil {
			return nil, false, fmt.Errorf("fetching linked user: %w", err)
		}
		return user, false, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, false, fmt.Errorf("looking up oauth account: %w", err)
	}

	// Step 2-5: Not linked. Use a transaction for atomicity.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Check if a user with this email exists.
	var user store.User
	created := false
	err = tx.QueryRow(ctx,
		`SELECT id, email, display_name, avatar_url, created_at, updated_at
		 FROM users WHERE lower(email) = lower($1)`, email,
	).Scan(&user.ID, &user.Email, &user.DisplayName, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// New user — create.
		user.ID = uuid.New()
		user.Email = email
		user.DisplayName = displayName
		user.AvatarURL = avatarURL
		now := time.Now()
		user.CreatedAt = now
		user.UpdatedAt = now
		created = true

		_, err = tx.Exec(ctx,
			`INSERT INTO users (id, email, display_name, avatar_url, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			user.ID, user.Email, user.DisplayName, user.AvatarURL, user.CreatedAt, user.UpdatedAt,
		)
		if err != nil {
			return nil, false, fmt.Errorf("creating user: %w", err)
		}
	} else if err != nil {
		return nil, false, fmt.Errorf("looking up user by email: %w", err)
	}

	// Link the OAuth account.
	now := time.Now()
	_, err = tx.Exec(ctx,
		`INSERT INTO oauth_accounts
		 (provider, provider_user_id, user_id, email, display_name, avatar_url,
		  access_token, refresh_token, expires_at, linked_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		acct.Provider, acct.ProviderUserID, user.ID, acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, now, now,
	)
	if err != nil {
		return nil, false, fmt.Errorf("linking oauth account: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("committing transaction: %w", err)
	}

	return &user, created, nil
}
