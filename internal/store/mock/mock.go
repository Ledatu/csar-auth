// Package mock provides an in-memory Store implementation for testing.
package mock

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
)

// Store is a thread-safe in-memory implementation of store.Store.
type Store struct {
	mu              sync.Mutex
	users           map[uuid.UUID]*store.User
	accounts        map[string]*store.OAuthAccount   // key: provider|provider_user_id
	serviceAccounts map[string]*store.ServiceAccount // key: name
}

// New returns a new mock Store.
func New() *Store {
	return &Store{
		users:           make(map[uuid.UUID]*store.User),
		accounts:        make(map[string]*store.OAuthAccount),
		serviceAccounts: make(map[string]*store.ServiceAccount),
	}
}

func oauthKey(provider, providerUserID string) string {
	return provider + "|" + providerUserID
}

func (s *Store) GetUserByID(_ context.Context, id uuid.UUID) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *Store) GetUserByEmail(_ context.Context, email string) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			cp := *u
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) GetUserByPhone(_ context.Context, phone string) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Phone == phone {
			cp := *u
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) CreateUser(_ context.Context, u *store.User) (*store.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	// Check email uniqueness.
	if u.Email != "" {
		for _, existing := range s.users {
			if strings.EqualFold(existing.Email, u.Email) {
				return nil, store.ErrUnverifiedEmailConflict
			}
		}
	}

	cp := *u
	s.users[u.ID] = &cp
	return u, nil
}

func (s *Store) UpdateUser(_ context.Context, u *store.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; !ok {
		return store.ErrNotFound
	}
	u.UpdatedAt = time.Now()
	cp := *u
	s.users[u.ID] = &cp
	return nil
}

func (s *Store) GetOAuthAccount(_ context.Context, provider, providerUserID string) (*store.OAuthAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[oauthKey(provider, providerUserID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *Store) GetOAuthAccountsByUserID(_ context.Context, userID uuid.UUID) ([]store.OAuthAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.OAuthAccount
	for _, a := range s.accounts {
		if a.UserID == userID {
			out = append(out, *a)
		}
	}
	return out, nil
}

func (s *Store) CreateOAuthAccount(_ context.Context, acct *store.OAuthAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oauthKey(acct.Provider, acct.ProviderUserID)
	if _, ok := s.accounts[key]; ok {
		return store.ErrProviderAlreadyLinked
	}
	now := time.Now()
	acct.LinkedAt = now
	acct.UpdatedAt = now
	cp := *acct
	s.accounts[key] = &cp
	return nil
}

func (s *Store) UpdateOAuthAccount(_ context.Context, acct *store.OAuthAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oauthKey(acct.Provider, acct.ProviderUserID)
	if _, ok := s.accounts[key]; !ok {
		return store.ErrNotFound
	}
	acct.UpdatedAt = time.Now()
	cp := *acct
	s.accounts[key] = &cp
	return nil
}

func (s *Store) DeleteOAuthAccount(_ context.Context, provider string, userID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, a := range s.accounts {
		if a.Provider == provider && a.UserID == userID {
			delete(s.accounts, key)
			return nil
		}
	}
	return nil
}

// FindOrCreateUser mirrors the production matching priority:
//  1. Exact provider+providerUserID match
//  2. Verified email match
//  3. Verified phone match (even if unverified email conflicts)
//  4. Create new user
func (s *Store) FindOrCreateUser(ctx context.Context, acct *store.OAuthAccount, email, phone, displayName, avatarURL string) (*store.User, store.FindOrCreateResult, error) {
	// Step 1: existing oauth link.
	existing, err := s.GetOAuthAccount(ctx, acct.Provider, acct.ProviderUserID)
	if err == nil {
		existing.AccessToken = acct.AccessToken
		existing.RefreshToken = acct.RefreshToken
		existing.ExpiresAt = acct.ExpiresAt
		existing.Email = acct.Email
		existing.DisplayName = acct.DisplayName
		existing.AvatarURL = acct.AvatarURL
		existing.EmailVerified = acct.EmailVerified
		_ = s.UpdateOAuthAccount(ctx, existing)
		user, _ := s.GetUserByID(ctx, existing.UserID)
		return user, store.ResultExistingLogin, nil
	}

	// Step 2: email match (verified only).
	var unverifiedEmailConflict bool
	if email != "" {
		user, err := s.GetUserByEmail(ctx, email)
		if err == nil {
			if acct.EmailVerified {
				acct.UserID = user.ID
				_ = s.CreateOAuthAccount(ctx, acct)
				return user, store.ResultLinkedToExisting, nil
			}
			unverifiedEmailConflict = true
		}
	}

	// Step 3: phone match.
	if phone != "" {
		user, err := s.GetUserByPhone(ctx, phone)
		if err == nil {
			acct.UserID = user.ID
			_ = s.CreateOAuthAccount(ctx, acct)
			return user, store.ResultLinkedToExisting, nil
		}
	}

	if unverifiedEmailConflict {
		return nil, 0, store.ErrUnverifiedEmailConflict
	}

	// Step 4: create new user.
	newUser := &store.User{
		ID:          uuid.New(),
		Email:       email,
		Phone:       phone,
		DisplayName: displayName,
		AvatarURL:   avatarURL,
	}
	created, err := s.CreateUser(ctx, newUser)
	if err != nil {
		return nil, 0, err
	}
	acct.UserID = created.ID
	_ = s.CreateOAuthAccount(ctx, acct)
	return created, store.ResultCreatedNewUser, nil
}

func (s *Store) LinkOAuthAccount(ctx context.Context, userID uuid.UUID, acct *store.OAuthAccount) error {
	existing, err := s.GetOAuthAccount(ctx, acct.Provider, acct.ProviderUserID)
	if err == nil {
		if existing.UserID == userID {
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
	acct.UserID = userID
	return s.CreateOAuthAccount(ctx, acct)
}

func (s *Store) CountOAuthAccounts(_ context.Context, userID uuid.UUID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.accounts {
		if a.UserID == userID {
			n++
		}
	}
	return n, nil
}

func (s *Store) ListActiveServiceAccounts(_ context.Context) ([]store.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []store.ServiceAccount
	for _, sa := range s.serviceAccounts {
		if sa.Status == "active" {
			out = append(out, *sa)
		}
	}
	return out, nil
}

func (s *Store) GetServiceAccount(_ context.Context, name string) (*store.ServiceAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.serviceAccounts[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sa
	return &cp, nil
}

func (s *Store) CreateServiceAccount(_ context.Context, sa *store.ServiceAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.serviceAccounts[sa.Name]; ok {
		return fmt.Errorf("service account %q already exists", sa.Name)
	}
	if sa.Status == "" {
		sa.Status = "active"
	}
	sa.CreatedAt = time.Now()
	cp := *sa
	s.serviceAccounts[sa.Name] = &cp
	return nil
}

func (s *Store) UpdateServiceAccountKey(_ context.Context, name, newPEM string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.serviceAccounts[name]
	if !ok || sa.Status != "active" {
		return store.ErrNotFound
	}
	sa.PublicKeyPEM = newPEM
	now := time.Now()
	sa.RotatedAt = &now
	return nil
}

func (s *Store) RevokeServiceAccount(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.serviceAccounts[name]
	if !ok || sa.Status != "active" {
		return store.ErrNotFound
	}
	sa.Status = "revoked"
	now := time.Now()
	sa.RevokedAt = &now
	return nil
}

func (s *Store) Migrate(_ context.Context) error { return nil }
func (s *Store) Close() error                    { return nil }

// SeedUser inserts a pre-existing user for test setup.
func (s *Store) SeedUser(u *store.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *u
	s.users[u.ID] = &cp
}
