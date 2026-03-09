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
	ErrNotFound = errors.New("not found")
)

// User represents an authenticated user with a stable internal UUID.
type User struct {
	ID          uuid.UUID
	Email       string
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
	LinkedAt       time.Time
	UpdatedAt      time.Time
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

	// FindOrCreateUser atomically performs the lookup-or-create flow:
	//  1. Check oauth_accounts for (provider, provider_user_id)
	//  2. If found, update tokens and return the linked user
	//  3. If not found, check users by email
	//  4. If user exists, create the oauth_account link
	//  5. If no user, create user + oauth_account in a transaction
	// Returns the user and whether it was newly created.
	FindOrCreateUser(ctx context.Context, acct *OAuthAccount, email, displayName, avatarURL string) (*User, bool, error)

	// Migrate runs schema migrations (idempotent).
	Migrate(ctx context.Context) error

	// Close releases resources (connection pool, etc.).
	Close() error
}
