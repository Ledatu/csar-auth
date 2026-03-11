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

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-core/pgutil"
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
	s := &Store{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}

	pool, err := pgutil.NewPool(ctx, dsn, pgutil.WithLogger(s.logger))
	if err != nil {
		return nil, err
	}
	s.pool = pool

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
		`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if pgutil.IsNotFound(err) {
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
		`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at
		 FROM users WHERE lower(email) = lower($1)`, email,
	).Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

func (s *Store) GetUserByPhone(ctx context.Context, phone string) (*store.User, error) {
	u := &store.User{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at
		 FROM users WHERE phone = $1`, phone,
	).Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by phone: %w", err)
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
		`INSERT INTO users (id, email, phone, display_name, avatar_url, created_at, updated_at)
		 VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6, $7)`,
		u.ID, u.Email, u.Phone, u.DisplayName, u.AvatarURL, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "idx_users_email_lower") {
			return nil, fmt.Errorf("user with email %q already exists: %w", u.Email, err)
		}
		if strings.Contains(err.Error(), "idx_users_phone") {
			return nil, fmt.Errorf("user with phone %q already exists: %w", u.Phone, err)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

func (s *Store) UpdateUser(ctx context.Context, u *store.User) error {
	u.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET email = NULLIF($2, ''), phone = NULLIF($3, ''),
		 display_name = $4, avatar_url = $5, updated_at = $6
		 WHERE id = $1`,
		u.ID, u.Email, u.Phone, u.DisplayName, u.AvatarURL, u.UpdatedAt,
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
		        access_token, refresh_token, expires_at, email_verified, linked_at, updated_at
		 FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&a.Provider, &a.ProviderUserID, &a.UserID, &a.Email, &a.DisplayName, &a.AvatarURL,
		&a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.EmailVerified, &a.LinkedAt, &a.UpdatedAt)
	if pgutil.IsNotFound(err) {
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
		        access_token, refresh_token, expires_at, email_verified, linked_at, updated_at
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
			&a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.EmailVerified, &a.LinkedAt, &a.UpdatedAt); err != nil {
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
		  access_token, refresh_token, expires_at, email_verified, linked_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		acct.Provider, acct.ProviderUserID, acct.UserID, acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, acct.EmailVerified, acct.LinkedAt, acct.UpdatedAt,
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
		     access_token = $6, refresh_token = $7, expires_at = $8,
		     email_verified = $9, updated_at = $10
		 WHERE provider = $1 AND provider_user_id = $2`,
		acct.Provider, acct.ProviderUserID,
		acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt,
		acct.EmailVerified, acct.UpdatedAt,
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

// FindOrCreateUser performs the lookup-or-create flow atomically.
// It attempts to match by email first, then by phone. Auto-linking on email
// requires the email to be verified. Phone matches auto-link unconditionally
// (Telegram always verifies phone numbers).
func (s *Store) FindOrCreateUser(ctx context.Context, acct *store.OAuthAccount, email, phone, displayName, avatarURL string) (*store.User, store.FindOrCreateResult, error) {
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
		existing.EmailVerified = acct.EmailVerified
		if err := s.UpdateOAuthAccount(ctx, existing); err != nil {
			return nil, 0, fmt.Errorf("updating existing oauth account: %w", err)
		}

		user, err := s.GetUserByID(ctx, existing.UserID)
		if err != nil {
			return nil, 0, fmt.Errorf("fetching linked user: %w", err)
		}
		return user, store.ResultExistingLogin, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, 0, fmt.Errorf("looking up oauth account: %w", err)
	}

	// Not linked yet. Use a transaction for atomicity.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Try to find an existing user by email.
	var unverifiedEmailConflict bool
	if email != "" {
		var user store.User
		err = tx.QueryRow(ctx,
			`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at
			 FROM users WHERE lower(email) = lower($1)`, email,
		).Scan(&user.ID, &user.Email, &user.Phone, &user.DisplayName, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt)

		if err == nil {
			if acct.EmailVerified {
				if err := s.insertOAuthAccountTx(ctx, tx, acct, user.ID); err != nil {
					return nil, 0, err
				}
				if err := tx.Commit(ctx); err != nil {
					return nil, 0, fmt.Errorf("committing transaction: %w", err)
				}
				return &user, store.ResultLinkedToExisting, nil
			}
			// Unverified email — don't block yet, fall through to phone match.
			unverifiedEmailConflict = true
		} else if !pgutil.IsNotFound(err) {
			return nil, 0, fmt.Errorf("looking up user by email: %w", err)
		}
	}

	// Try to find an existing user by phone.
	if phone != "" {
		var user store.User
		err = tx.QueryRow(ctx,
			`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at
			 FROM users WHERE phone = $1`, phone,
		).Scan(&user.ID, &user.Email, &user.Phone, &user.DisplayName, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt)

		if err == nil {
			if err := s.insertOAuthAccountTx(ctx, tx, acct, user.ID); err != nil {
				return nil, 0, err
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, 0, fmt.Errorf("committing transaction: %w", err)
			}
			return &user, store.ResultLinkedToExisting, nil
		}
		if !pgutil.IsNotFound(err) {
			return nil, 0, fmt.Errorf("looking up user by phone: %w", err)
		}
	}

	// If email matched but was unverified and no phone match was found, report the conflict.
	if unverifiedEmailConflict {
		return nil, 0, store.ErrUnverifiedEmailConflict
	}

	// No match — create new user + link.
	newUser := store.User{
		ID:          uuid.New(),
		Email:       email,
		Phone:       phone,
		DisplayName: displayName,
		AvatarURL:   avatarURL,
	}
	now := time.Now()
	newUser.CreatedAt = now
	newUser.UpdatedAt = now

	_, err = tx.Exec(ctx,
		`INSERT INTO users (id, email, phone, display_name, avatar_url, created_at, updated_at)
		 VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6, $7)`,
		newUser.ID, newUser.Email, newUser.Phone, newUser.DisplayName, newUser.AvatarURL, newUser.CreatedAt, newUser.UpdatedAt,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("creating user: %w", err)
	}

	if err := s.insertOAuthAccountTx(ctx, tx, acct, newUser.ID); err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("committing transaction: %w", err)
	}
	return &newUser, store.ResultCreatedNewUser, nil
}

// insertOAuthAccountTx inserts an oauth_account row within a transaction.
func (s *Store) insertOAuthAccountTx(ctx context.Context, tx pgx.Tx, acct *store.OAuthAccount, userID uuid.UUID) error {
	now := time.Now()
	_, err := tx.Exec(ctx,
		`INSERT INTO oauth_accounts
		 (provider, provider_user_id, user_id, email, display_name, avatar_url,
		  access_token, refresh_token, expires_at, email_verified, linked_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		acct.Provider, acct.ProviderUserID, userID, acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, acct.EmailVerified, now, now,
	)
	if err != nil {
		return fmt.Errorf("linking oauth account: %w", err)
	}
	return nil
}

// LinkOAuthAccount links an OAuth identity to an authenticated user.
// Returns ErrProviderAlreadyLinked if the provider account is linked to a different user.
func (s *Store) LinkOAuthAccount(ctx context.Context, userID uuid.UUID, acct *store.OAuthAccount) error {
	// Check if this provider account is already linked to someone.
	existing, err := s.GetOAuthAccount(ctx, acct.Provider, acct.ProviderUserID)
	if err == nil {
		if existing.UserID == userID {
			// Already linked to this user — update tokens.
			existing.AccessToken = acct.AccessToken
			existing.RefreshToken = acct.RefreshToken
			existing.ExpiresAt = acct.ExpiresAt
			existing.Email = acct.Email
			existing.DisplayName = acct.DisplayName
			existing.AvatarURL = acct.AvatarURL
			existing.EmailVerified = acct.EmailVerified
			return s.UpdateOAuthAccount(ctx, existing)
		}
		return store.ErrProviderAlreadyLinked
	}
	if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("checking existing link: %w", err)
	}

	acct.UserID = userID
	return s.CreateOAuthAccount(ctx, acct)
}

// CountOAuthAccounts returns the number of linked OAuth accounts for a user.
func (s *Store) CountOAuthAccounts(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_accounts WHERE user_id = $1`, userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting oauth accounts: %w", err)
	}
	return count, nil
}
