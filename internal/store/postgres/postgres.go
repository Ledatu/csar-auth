// Package postgres implements the store.Store interface using PostgreSQL (pgx/v5).
package postgres

import (
	"context"
	"encoding/json"
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
		`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at, merged_into, merged_at
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt, &u.MergedInto, &u.MergedAt)
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
		`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at, merged_into, merged_at
		 FROM users WHERE lower(email) = lower($1) AND merged_into IS NULL`, email,
	).Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt, &u.MergedInto, &u.MergedAt)
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
		`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at, merged_into, merged_at
		 FROM users WHERE phone = $1 AND merged_into IS NULL`, phone,
	).Scan(&u.ID, &u.Email, &u.Phone, &u.DisplayName, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt, &u.MergedInto, &u.MergedAt)
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
		        access_token, refresh_token, expires_at, email_verified, linked_at, updated_at,
		        provider_metadata
		 FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2`,
		provider, providerUserID,
	).Scan(&a.Provider, &a.ProviderUserID, &a.UserID, &a.Email, &a.DisplayName, &a.AvatarURL,
		&a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.EmailVerified, &a.LinkedAt, &a.UpdatedAt,
		&a.ProviderMetadata)
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
		        access_token, refresh_token, expires_at, email_verified, linked_at, updated_at,
		        provider_metadata
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
			&a.AccessToken, &a.RefreshToken, &a.ExpiresAt, &a.EmailVerified, &a.LinkedAt, &a.UpdatedAt,
			&a.ProviderMetadata); err != nil {
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
		  access_token, refresh_token, expires_at, email_verified, linked_at, updated_at,
		  provider_metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		acct.Provider, acct.ProviderUserID, acct.UserID, acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, acct.EmailVerified, acct.LinkedAt, acct.UpdatedAt,
		metadataJSON(acct.ProviderMetadata),
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
		     email_verified = $9, updated_at = $10,
		     provider_metadata = COALESCE($11, provider_metadata)
		 WHERE provider = $1 AND provider_user_id = $2`,
		acct.Provider, acct.ProviderUserID,
		acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt,
		acct.EmailVerified, acct.UpdatedAt,
		metadataJSON(acct.ProviderMetadata),
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
		if user.Phone == "" && phone != "" {
			if _, err := s.pool.Exec(ctx,
				`UPDATE users SET phone = $1, updated_at = now() WHERE id = $2 AND phone IS NULL`,
				phone, user.ID,
			); err != nil {
				s.logger.Warn("failed to backfill phone on login", "user_id", user.ID, "error", err)
			} else {
				user.Phone = phone
			}
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

	// Try to find an existing user by email (skip merged accounts).
	var unverifiedEmailConflict bool
	if email != "" {
		var user store.User
		err = tx.QueryRow(ctx,
			`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at, merged_into, merged_at
			 FROM users WHERE lower(email) = lower($1) AND merged_into IS NULL`, email,
		).Scan(&user.ID, &user.Email, &user.Phone, &user.DisplayName, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt, &user.MergedInto, &user.MergedAt)

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

	// Try to find an existing user by phone (skip merged accounts).
	if phone != "" {
		var user store.User
		err = tx.QueryRow(ctx,
			`SELECT id, COALESCE(email, ''), COALESCE(phone, ''), display_name, avatar_url, created_at, updated_at, merged_into, merged_at
			 FROM users WHERE phone = $1 AND merged_into IS NULL`, phone,
		).Scan(&user.ID, &user.Email, &user.Phone, &user.DisplayName, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt, &user.MergedInto, &user.MergedAt)

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
		  access_token, refresh_token, expires_at, email_verified, linked_at, updated_at,
		  provider_metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		acct.Provider, acct.ProviderUserID, userID, acct.Email, acct.DisplayName, acct.AvatarURL,
		acct.AccessToken, acct.RefreshToken, acct.ExpiresAt, acct.EmailVerified, now, now,
		metadataJSON(acct.ProviderMetadata),
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

// --- Bot Verification ---

func (s *Store) CreateBotVerification(ctx context.Context, v *store.BotVerification) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO bot_verifications
		 (id, code_hash, intent, user_id, status, created_at, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		v.ID, v.CodeHash, v.Intent, v.UserID, v.Status, v.CreatedAt, v.ExpiresAt, v.UserAgent, v.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("creating bot verification: %w", err)
	}
	return nil
}

func (s *Store) GetBotVerification(ctx context.Context, id uuid.UUID) (*store.BotVerification, error) {
	v := &store.BotVerification{}
	err := s.pool.QueryRow(ctx,
		`SELECT id, code_hash, intent, user_id, provider, provider_user_id, provider_display,
		        status, created_at, expires_at, confirmed_at, consumed_at, user_agent, ip_address
		 FROM bot_verifications WHERE id = $1`, id,
	).Scan(&v.ID, &v.CodeHash, &v.Intent, &v.UserID, &v.Provider, &v.ProviderUserID, &v.ProviderDisplay,
		&v.Status, &v.CreatedAt, &v.ExpiresAt, &v.ConfirmedAt, &v.ConsumedAt, &v.UserAgent, &v.IPAddress)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get bot verification: %w", err)
	}
	return v, nil
}

func (s *Store) ConfirmBotVerification(ctx context.Context, codeHash, provider, providerUserID, displayName string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE bot_verifications
		 SET status = 'confirmed',
		     provider = $2,
		     provider_user_id = $3,
		     provider_display = $4,
		     confirmed_at = now()
		 WHERE code_hash = $1
		   AND status = 'pending'
		   AND expires_at > now()`,
		codeHash, provider, providerUserID, displayName,
	)
	if err != nil {
		return fmt.Errorf("confirming bot verification: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *Store) ConsumeBotVerification(ctx context.Context, id uuid.UUID) (*store.BotVerification, error) {
	v := &store.BotVerification{}
	err := s.pool.QueryRow(ctx,
		`UPDATE bot_verifications
		 SET status = 'consumed', consumed_at = now()
		 WHERE id = $1 AND status = 'confirmed' AND expires_at > now()
		 RETURNING id, code_hash, intent, user_id, provider, provider_user_id, provider_display,
		           status, created_at, expires_at, confirmed_at, consumed_at, user_agent, ip_address`,
		id,
	).Scan(&v.ID, &v.CodeHash, &v.Intent, &v.UserID, &v.Provider, &v.ProviderUserID, &v.ProviderDisplay,
		&v.Status, &v.CreatedAt, &v.ExpiresAt, &v.ConfirmedAt, &v.ConsumedAt, &v.UserAgent, &v.IPAddress)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consuming bot verification: %w", err)
	}
	return v, nil
}

func (s *Store) CleanExpiredBotVerifications(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE bot_verifications
		 SET status = 'expired'
		 WHERE status IN ('pending', 'confirmed')
		   AND expires_at <= now()`,
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning expired bot verifications: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) CountPendingBotVerifications(ctx context.Context, ipAddress string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM bot_verifications
		 WHERE ip_address = $1 AND status = 'pending' AND expires_at > now()`,
		ipAddress,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting pending bot verifications: %w", err)
	}
	return count, nil
}

// --- Telegram ID migration ---

func (s *Store) MigrateTelegramID(ctx context.Context, oldID, newID string, metadata map[string]interface{}) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin telegram ID migration tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Check whether newID already exists.
	var existingUserID *uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT user_id FROM oauth_accounts
		 WHERE provider = 'telegram' AND provider_user_id = $1`,
		newID,
	).Scan(&existingUserID)
	newExists := err == nil

	metaBytes := metadataJSON(metadata)

	if newExists {
		// newID is already linked. Delete the stale oldID entry
		// only if it points to the same user (avoid cross-user damage).
		tag, err := tx.Exec(ctx,
			`DELETE FROM oauth_accounts
			 WHERE provider = 'telegram' AND provider_user_id = $1 AND user_id = $2`,
			oldID, existingUserID,
		)
		if err != nil {
			return false, fmt.Errorf("deleting stale entry: %w", err)
		}
		// Also update metadata on the surviving row.
		if metaBytes != nil {
			if _, err := tx.Exec(ctx,
				`UPDATE oauth_accounts SET provider_metadata = $2, updated_at = now()
				 WHERE provider = 'telegram' AND provider_user_id = $1`,
				newID, metaBytes,
			); err != nil {
				return false, fmt.Errorf("updating metadata on surviving row: %w", err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("committing stale cleanup: %w", err)
		}
		return tag.RowsAffected() > 0, nil
	}

	// newID does not exist yet -- rename oldID entry.
	tag, err := tx.Exec(ctx,
		`UPDATE oauth_accounts
		 SET provider_user_id = $2, provider_metadata = COALESCE($3, provider_metadata), updated_at = now()
		 WHERE provider = 'telegram' AND provider_user_id = $1`,
		oldID, newID, metaBytes,
	)
	if err != nil {
		return false, fmt.Errorf("migrating telegram ID: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("committing telegram ID migration: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// --- Account Merge ---

func (s *Store) CreateMergeRecord(ctx context.Context, rec *store.MergeRecord) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO merge_records (id, token_hash, source_user, target_user, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		rec.ID, rec.TokenHash, rec.SourceUser, rec.TargetUser, rec.CreatedAt, rec.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("creating merge record: %w", err)
	}
	return nil
}

func (s *Store) ConsumeMergeRecord(ctx context.Context, tokenHash string, targetUser uuid.UUID) (*store.MergeRecord, error) {
	rec := &store.MergeRecord{}
	err := s.pool.QueryRow(ctx,
		`UPDATE merge_records
		 SET consumed_at = now()
		 WHERE token_hash = $1
		   AND target_user = $2
		   AND consumed_at IS NULL
		   AND expires_at > now()
		 RETURNING id, token_hash, source_user, target_user, created_at, expires_at, consumed_at, authz_completed_at`,
		tokenHash, targetUser,
	).Scan(&rec.ID, &rec.TokenHash, &rec.SourceUser, &rec.TargetUser, &rec.CreatedAt, &rec.ExpiresAt, &rec.ConsumedAt, &rec.AuthzCompletedAt)
	if pgutil.IsNotFound(err) {
		return nil, store.ErrMergeTokenExpired
	}
	if err != nil {
		return nil, fmt.Errorf("consuming merge record: %w", err)
	}
	return rec, nil
}

func (s *Store) MergeUsers(ctx context.Context, targetID, sourceID uuid.UUID) error {
	if targetID == sourceID {
		return store.ErrSelfMerge
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning merge transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock both user rows in consistent order to prevent deadlocks.
	lo, hi := targetID, sourceID
	if lo.String() > hi.String() {
		lo, hi = hi, lo
	}
	var loMergedInto, hiMergedInto *uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT merged_into FROM users WHERE id = $1 FOR UPDATE`, lo,
	).Scan(&loMergedInto)
	if err != nil {
		return fmt.Errorf("locking user %s: %w", lo, err)
	}
	err = tx.QueryRow(ctx,
		`SELECT merged_into FROM users WHERE id = $1 FOR UPDATE`, hi,
	).Scan(&hiMergedInto)
	if err != nil {
		return fmt.Errorf("locking user %s: %w", hi, err)
	}

	// Check the source is not already merged.
	sourceMergedInto := loMergedInto
	if sourceID == hi {
		sourceMergedInto = hiMergedInto
	}
	if sourceMergedInto != nil {
		return store.ErrUserAlreadyMerged
	}

	// Move all OAuth accounts from source to target.
	if _, err := tx.Exec(ctx,
		`UPDATE oauth_accounts SET user_id = $1, updated_at = now() WHERE user_id = $2`,
		targetID, sourceID,
	); err != nil {
		return fmt.Errorf("moving oauth accounts: %w", err)
	}

	// Revoke all source sessions.
	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		sourceID,
	); err != nil {
		return fmt.Errorf("revoking source sessions: %w", err)
	}

	// Smart profile merge: read source values, then NULL them on source
	// to release unique index slots, then copy into target gaps.
	var srcEmail, srcPhone, srcDisplayName, srcAvatarURL *string
	err = tx.QueryRow(ctx,
		`SELECT email, phone, display_name, avatar_url FROM users WHERE id = $1`, sourceID,
	).Scan(&srcEmail, &srcPhone, &srcDisplayName, &srcAvatarURL)
	if err != nil {
		return fmt.Errorf("reading source profile: %w", err)
	}

	// Clear unique fields on source first to avoid index conflicts.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET email = NULL, phone = NULL WHERE id = $1`, sourceID,
	); err != nil {
		return fmt.Errorf("clearing source unique fields: %w", err)
	}

	// Now safely fill target gaps from the source values we captured.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET
		   email = CASE WHEN COALESCE(email, '') = '' THEN $2 ELSE email END,
		   phone = CASE WHEN COALESCE(phone, '') = '' THEN $3 ELSE phone END,
		   display_name = CASE WHEN display_name = '' AND $4 != '' THEN $4 ELSE display_name END,
		   avatar_url = CASE WHEN avatar_url = '' AND $5 != '' THEN $5 ELSE avatar_url END,
		   updated_at = now()
		 WHERE id = $1`,
		targetID, srcEmail, srcPhone, derefStr(srcDisplayName), derefStr(srcAvatarURL),
	); err != nil {
		return fmt.Errorf("merging profile: %w", err)
	}

	// Soft-delete source.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET merged_into = $1, merged_at = now() WHERE id = $2`,
		targetID, sourceID,
	); err != nil {
		return fmt.Errorf("soft-deleting source: %w", err)
	}

	return tx.Commit(ctx)
}

func (s *Store) MarkMergeAuthzComplete(ctx context.Context, recordID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE merge_records SET authz_completed_at = now() WHERE id = $1`,
		recordID,
	)
	if err != nil {
		return fmt.Errorf("marking authz complete: %w", err)
	}
	return nil
}

func (s *Store) GetPendingAuthzMerges(ctx context.Context) ([]store.MergeRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, token_hash, source_user, target_user, created_at, expires_at, consumed_at, authz_completed_at
		 FROM merge_records
		 WHERE consumed_at IS NOT NULL AND authz_completed_at IS NULL
		 ORDER BY consumed_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("querying pending authz merges: %w", err)
	}
	defer rows.Close()

	var recs []store.MergeRecord
	for rows.Next() {
		var r store.MergeRecord
		if err := rows.Scan(&r.ID, &r.TokenHash, &r.SourceUser, &r.TargetUser, &r.CreatedAt, &r.ExpiresAt, &r.ConsumedAt, &r.AuthzCompletedAt); err != nil {
			return nil, fmt.Errorf("scanning merge record: %w", err)
		}
		recs = append(recs, r)
	}
	return recs, rows.Err()
}

// metadataJSON returns a []byte for JSONB insertion, or nil if the map is empty.
func metadataJSON(m map[string]interface{}) []byte {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
