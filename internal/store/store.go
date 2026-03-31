// Package store defines the persistence interface for csar-authn.
//
// The Store interface abstracts user and OAuth account storage,
// allowing implementations for PostgreSQL, MongoDB, YDB, etc.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors returned by Store implementations.
var (
	ErrNotFound                = errors.New("not found")
	ErrUnverifiedEmailConflict = errors.New("email matches existing user but provider email is not verified")
	ErrProviderAlreadyLinked   = errors.New("provider account is already linked to another user")
	ErrMergeTokenExpired       = errors.New("merge token expired or already consumed")
	ErrUserAlreadyMerged       = errors.New("source user has already been merged")
	ErrSelfMerge               = errors.New("cannot merge a user into itself")
)

// FindOrCreateResult indicates the outcome of FindOrCreateUser.
type FindOrCreateResult int

const (
	ResultExistingLogin    FindOrCreateResult = iota // Existing oauth link, user logged in
	ResultLinkedToExisting                           // Auto-linked to existing user via verified email
	ResultCreatedNewUser                             // Brand new user + oauth link created
)

// User represents an authenticated user with a stable internal UUID.
type User struct {
	ID          uuid.UUID
	Email       string
	Phone       string
	DisplayName string
	AvatarURL   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	MergedInto  *uuid.UUID
	MergedAt    *time.Time
}

// MergeRecord tracks a pending or completed account merge.
type MergeRecord struct {
	ID               uuid.UUID
	TokenHash        string
	SourceUser       uuid.UUID
	TargetUser       uuid.UUID
	CreatedAt        time.Time
	ExpiresAt        time.Time
	ConsumedAt       *time.Time
	AuthzCompletedAt *time.Time
}

// OAuthAccount links a provider identity to an internal user.
type OAuthAccount struct {
	Provider         string
	ProviderUserID   string
	UserID           uuid.UUID
	Email            string
	DisplayName      string
	AvatarURL        string
	AccessToken      string
	RefreshToken     string
	ExpiresAt        *time.Time
	EmailVerified    bool
	LinkedAt         time.Time
	UpdatedAt        time.Time
	ProviderMetadata map[string]interface{} // provider-specific data (e.g. Telegram OIDC sub)
}

// BotVerification tracks a pending bot-based identity verification.
type BotVerification struct {
	ID              uuid.UUID
	CodeHash        string
	Intent          string     // "login" or "link"
	UserID          *uuid.UUID // non-nil when intent=link
	Provider        string
	ProviderUserID  string
	ProviderDisplay string
	Status          string // pending, confirmed, consumed, expired
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ConfirmedAt     *time.Time
	ConsumedAt      *time.Time
	UserAgent       string
	IPAddress       string
}

// Session represents a server-side session backed by the sessions table.
type Session struct {
	ID         string
	UserID     uuid.UUID
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	UserAgent  string
	IPAddress  string
	RevokedAt  *time.Time
}

// AdminSessionListParams configures pagination and filters for platform-admin session listing.
type AdminSessionListParams struct {
	UserID *uuid.UUID
	Email  string
	Status string
	Limit  int
	Offset int
}

// AdminSessionRow is a session joined with the owning user's email.
type AdminSessionRow struct {
	Session
	UserEmail string
}

// UserSearchParams configures a bounded admin user lookup.
type UserSearchParams struct {
	Query string
	Limit int
}

// UserSearchResult is a browser-safe user summary for admin lookup flows.
type UserSearchResult struct {
	ID          uuid.UUID
	Email       string
	DisplayName string
	AvatarURL   string
}

// ServiceAccount represents an STS service account stored in the database.
type ServiceAccount struct {
	Name              string
	PublicKeyPEM      string
	AllowedAudiences  []string
	AllowAllAudiences bool
	TokenTTL          time.Duration
	Status            string // "active" or "revoked"
	CreatedAt         time.Time
	RotatedAt         *time.Time
	RevokedAt         *time.Time
}

// Store defines the persistence contract for csar-authn.
// Implementations must be safe for concurrent use.
type Store interface {
	// GetUserByID returns a user by primary key.
	// Returns ErrNotFound if the user does not exist.
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)

	// GetUserByEmail returns a user by email (case-insensitive).
	// Returns ErrNotFound if no user with that email exists.
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// CreateUser inserts a new user. The ID field may be zero; the
	// implementation generates a UUID and returns the created record.
	CreateUser(ctx context.Context, u *User) (*User, error)

	// UpdateUser updates mutable fields (display_name, avatar_url, email).
	UpdateUser(ctx context.Context, u *User) error

	// GetOAuthAccount looks up a linked account by (provider, provider_user_id).
	// Returns ErrNotFound if no link exists.
	GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*OAuthAccount, error)

	// GetOAuthAccountsByUserID returns all linked accounts for a user.
	GetOAuthAccountsByUserID(ctx context.Context, userID uuid.UUID) ([]OAuthAccount, error)

	// CreateOAuthAccount links a new OAuth identity to a user.
	CreateOAuthAccount(ctx context.Context, acct *OAuthAccount) error

	// UpdateOAuthAccount updates tokens and metadata for an existing link.
	UpdateOAuthAccount(ctx context.Context, acct *OAuthAccount) error

	// DeleteOAuthAccount removes a linked account.
	DeleteOAuthAccount(ctx context.Context, provider string, userID uuid.UUID) error

	// GetUserByPhone returns a user by phone number.
	// Returns ErrNotFound if no user with that phone exists.
	GetUserByPhone(ctx context.Context, phone string) (*User, error)

	// FindOrCreateUser atomically performs the lookup-or-create flow:
	//  1. Check oauth_accounts for (provider, provider_user_id)
	//  2. If found, update tokens and return the linked user
	//  3. If email non-empty, check users by email; auto-link if verified
	//  4. If phone non-empty, check users by phone; auto-link (phone is verified)
	//  5. If no match, create user + oauth_account in a transaction
	FindOrCreateUser(ctx context.Context, acct *OAuthAccount, email, phone, displayName, avatarURL string) (*User, FindOrCreateResult, error)

	// LinkOAuthAccount links an OAuth identity to an authenticated user.
	// Returns ErrProviderAlreadyLinked if the provider account is linked to a different user.
	LinkOAuthAccount(ctx context.Context, userID uuid.UUID, acct *OAuthAccount) error

	// CountOAuthAccounts returns the number of linked OAuth accounts for a user.
	CountOAuthAccounts(ctx context.Context, userID uuid.UUID) (int, error)

	// ListActiveServiceAccounts returns all service accounts with status "active".
	ListActiveServiceAccounts(ctx context.Context) ([]ServiceAccount, error)

	// GetServiceAccount returns a service account by name (any status).
	// Returns ErrNotFound if the service account does not exist.
	GetServiceAccount(ctx context.Context, name string) (*ServiceAccount, error)

	// CreateServiceAccount inserts a new service account.
	CreateServiceAccount(ctx context.Context, sa *ServiceAccount) error

	// UpdateServiceAccountKey rotates the public key for an active service account.
	// Returns ErrNotFound if the service account does not exist or is not active.
	UpdateServiceAccountKey(ctx context.Context, name, newPEM string) error

	// RevokeServiceAccount soft-deletes a service account by setting status to "revoked".
	// Returns ErrNotFound if the service account does not exist.
	RevokeServiceAccount(ctx context.Context, name string) error

	// CreateSession inserts a new session row.
	CreateSession(ctx context.Context, s *Session) error

	// GetSession returns a session by ID. Returns ErrNotFound if missing.
	GetSession(ctx context.Context, sessionID string) (*Session, error)

	// TouchSession updates last_seen_at and expires_at for an active session.
	TouchSession(ctx context.Context, sessionID string, now time.Time, newExpiresAt time.Time) error

	// RevokeSession marks a session as revoked.
	RevokeSession(ctx context.Context, sessionID string) error

	// RevokeUserSessions revokes all active sessions for a user ("log out everywhere").
	RevokeUserSessions(ctx context.Context, userID uuid.UUID) error

	// DeleteExpiredSessions purges sessions that are expired or revoked.
	// Returns the number of rows deleted.
	DeleteExpiredSessions(ctx context.Context) (int64, error)

	// ListUserSessions returns all non-revoked, non-expired sessions for a user.
	ListUserSessions(ctx context.Context, userID uuid.UUID) ([]Session, error)

	// ListAdminSessions returns sessions for platform administration dashboards.
	// The boolean reports whether more rows exist beyond the current page.
	ListAdminSessions(ctx context.Context, params AdminSessionListParams) ([]AdminSessionRow, bool, error)

	// RevokeAdminSession revokes an active session by its opaque admin-facing ID.
	// Returns ErrNotFound if the session does not exist or is already inactive.
	RevokeAdminSession(ctx context.Context, adminSessionID string) (*AdminSessionRow, error)

	// SearchUsers returns bounded browser-safe user summaries for admin lookup flows.
	// Implementations should exclude merged users and respect the requested limit.
	SearchUsers(ctx context.Context, params UserSearchParams) ([]UserSearchResult, error)

	// --- Account Merge ---

	// CreateMergeRecord stores a new merge record with a hashed token.
	CreateMergeRecord(ctx context.Context, rec *MergeRecord) error

	// ConsumeMergeRecord atomically marks a merge record as consumed.
	// Returns ErrMergeTokenExpired if the record is missing, expired, or already consumed.
	// Validates that targetUser matches the record's target.
	ConsumeMergeRecord(ctx context.Context, tokenHash string, targetUser uuid.UUID) (*MergeRecord, error)

	// MergeUsers transfers all data from source to target in a single transaction:
	// moves oauth_accounts, revokes source sessions, smart-merges profile, soft-deletes source.
	// Returns ErrSelfMerge if source == target, ErrUserAlreadyMerged if source is already merged.
	MergeUsers(ctx context.Context, targetID, sourceID uuid.UUID) error

	// MarkMergeAuthzComplete sets authz_completed_at on a consumed merge record.
	MarkMergeAuthzComplete(ctx context.Context, recordID uuid.UUID) error

	// GetPendingAuthzMerges returns consumed merge records where authz has not yet completed.
	GetPendingAuthzMerges(ctx context.Context) ([]MergeRecord, error)

	// --- Bot Verification ---

	// CreateBotVerification inserts a new pending bot verification record.
	CreateBotVerification(ctx context.Context, v *BotVerification) error

	// GetBotVerification returns a bot verification by ID.
	// Returns ErrNotFound if the record does not exist.
	GetBotVerification(ctx context.Context, id uuid.UUID) (*BotVerification, error)

	// ConfirmBotVerification atomically confirms a pending, non-expired verification
	// matched by code_hash. Fills provider identity fields and sets status to confirmed.
	// Returns ErrNotFound if no matching pending record exists.
	ConfirmBotVerification(ctx context.Context, codeHash, provider, providerUserID, displayName string) error

	// ConsumeBotVerification atomically transitions a confirmed verification to consumed.
	// Returns the full record for session/link creation.
	// Returns ErrNotFound if the record is not in confirmed state.
	ConsumeBotVerification(ctx context.Context, id uuid.UUID) (*BotVerification, error)

	// CleanExpiredBotVerifications marks pending/confirmed rows past expires_at as expired.
	// Returns the number of rows updated.
	CleanExpiredBotVerifications(ctx context.Context) (int64, error)

	// CountPendingBotVerifications counts active pending verifications by IP address.
	CountPendingBotVerifications(ctx context.Context, ipAddress string) (int, error)

	// MigrateTelegramID atomically migrates a Telegram oauth_account's
	// provider_user_id from oldID to newID, storing metadata on the surviving row.
	// If newID already exists for the same user, oldID is deleted (stale cleanup).
	// If newID exists for a different user, no change is made.
	// Returns true if a row was updated or cleaned up.
	MigrateTelegramID(ctx context.Context, oldID, newID string, metadata map[string]interface{}) (bool, error)

	// Migrate runs schema migrations (idempotent).
	Migrate(ctx context.Context) error

	// Close releases resources (connection pool, etc.).
	Close() error
}
