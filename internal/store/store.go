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
)

// FindOrCreateResult indicates the outcome of FindOrCreateUser.
type FindOrCreateResult int

const (
	ResultExistingLogin    FindOrCreateResult = iota // Existing oauth link, user logged in
	ResultLinkedToExisting                            // Auto-linked to existing user via verified email
	ResultCreatedNewUser                              // Brand new user + oauth link created
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
}

// OAuthAccount links a provider identity to an internal user.
type OAuthAccount struct {
	Provider       string
	ProviderUserID string
	UserID         uuid.UUID
	Email          string
	DisplayName    string
	AvatarURL      string
	AccessToken    string
	RefreshToken   string
	ExpiresAt      *time.Time
	EmailVerified  bool
	LinkedAt       time.Time
	UpdatedAt      time.Time
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

	// Migrate runs schema migrations (idempotent).
	Migrate(ctx context.Context) error

	// Close releases resources (connection pool, etc.).
	Close() error
}
