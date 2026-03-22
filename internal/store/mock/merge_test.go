package mock_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func setupMergeFixture(t *testing.T) (*mock.Store, *store.User, *store.User) {
	t.Helper()
	s := mock.New()
	ctx := context.Background()

	userA := &store.User{ID: uuid.New(), Email: "a@example.com", DisplayName: "User A"}
	userB := &store.User{ID: uuid.New(), Phone: "+1111111111", DisplayName: "User B", AvatarURL: "https://avatar.b"}
	s.SeedUser(userA)
	s.SeedUser(userB)

	// Link provider accounts.
	_ = s.CreateOAuthAccount(ctx, &store.OAuthAccount{
		Provider: "telegram", ProviderUserID: "tg-1", UserID: userA.ID,
	})
	_ = s.CreateOAuthAccount(ctx, &store.OAuthAccount{
		Provider: "yandex", ProviderUserID: "ya-1", UserID: userB.ID,
	})

	// Create a session for B.
	_ = s.CreateSession(ctx, &store.Session{
		ID: "sess-b", UserID: userB.ID,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})

	return s, userA, userB
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func TestMergeUsers_HappyPath(t *testing.T) {
	s, userA, userB := setupMergeFixture(t)
	ctx := context.Background()

	if err := s.MergeUsers(ctx, userA.ID, userB.ID); err != nil {
		t.Fatal(err)
	}

	// B's OAuth account should now belong to A.
	accts, _ := s.GetOAuthAccountsByUserID(ctx, userA.ID)
	if len(accts) != 2 {
		t.Fatalf("expected 2 accounts on target, got %d", len(accts))
	}

	// B should be soft-deleted.
	merged, _ := s.GetUserByID(ctx, userB.ID)
	if merged.MergedInto == nil || *merged.MergedInto != userA.ID {
		t.Fatal("source user should have merged_into set")
	}

	// A should have B's phone (smart merge).
	target, _ := s.GetUserByID(ctx, userA.ID)
	if target.Phone != "+1111111111" {
		t.Fatalf("expected phone to be merged, got %q", target.Phone)
	}
	if target.AvatarURL != "https://avatar.b" {
		t.Fatalf("expected avatar to be merged from source, got %q", target.AvatarURL)
	}

	// B's sessions should be revoked.
	sessB, _ := s.GetSession(ctx, "sess-b")
	if sessB.RevokedAt == nil {
		t.Fatal("source user's sessions should be revoked")
	}
}

func TestMergeUsers_SelfMerge(t *testing.T) {
	s, userA, _ := setupMergeFixture(t)
	err := s.MergeUsers(context.Background(), userA.ID, userA.ID)
	if !errors.Is(err, store.ErrSelfMerge) {
		t.Fatalf("expected ErrSelfMerge, got %v", err)
	}
}

func TestMergeUsers_AlreadyMerged(t *testing.T) {
	s, userA, userB := setupMergeFixture(t)
	ctx := context.Background()

	if err := s.MergeUsers(ctx, userA.ID, userB.ID); err != nil {
		t.Fatal(err)
	}

	// Merging B again should fail.
	err := s.MergeUsers(ctx, userA.ID, userB.ID)
	if !errors.Is(err, store.ErrUserAlreadyMerged) {
		t.Fatalf("expected ErrUserAlreadyMerged, got %v", err)
	}
}

func TestConsumeMergeRecord_HappyPath(t *testing.T) {
	s, userA, userB := setupMergeFixture(t)
	ctx := context.Background()

	rec := &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  hashToken("test-token"),
		SourceUser: userB.ID,
		TargetUser: userA.ID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	_ = s.CreateMergeRecord(ctx, rec)

	consumed, err := s.ConsumeMergeRecord(ctx, hashToken("test-token"), userA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.SourceUser != userB.ID {
		t.Fatal("wrong source user")
	}
}

func TestConsumeMergeRecord_DoubleConsume(t *testing.T) {
	s, userA, userB := setupMergeFixture(t)
	ctx := context.Background()

	rec := &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  hashToken("once-only"),
		SourceUser: userB.ID,
		TargetUser: userA.ID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	_ = s.CreateMergeRecord(ctx, rec)
	_, _ = s.ConsumeMergeRecord(ctx, hashToken("once-only"), userA.ID)

	_, err := s.ConsumeMergeRecord(ctx, hashToken("once-only"), userA.ID)
	if !errors.Is(err, store.ErrMergeTokenExpired) {
		t.Fatalf("expected ErrMergeTokenExpired on double consume, got %v", err)
	}
}

func TestConsumeMergeRecord_Expired(t *testing.T) {
	s, userA, userB := setupMergeFixture(t)
	ctx := context.Background()

	rec := &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  hashToken("expired-token"),
		SourceUser: userB.ID,
		TargetUser: userA.ID,
		CreatedAt:  time.Now().Add(-10 * time.Minute),
		ExpiresAt:  time.Now().Add(-1 * time.Minute),
	}
	_ = s.CreateMergeRecord(ctx, rec)

	_, err := s.ConsumeMergeRecord(ctx, hashToken("expired-token"), userA.ID)
	if !errors.Is(err, store.ErrMergeTokenExpired) {
		t.Fatalf("expected ErrMergeTokenExpired for expired record, got %v", err)
	}
}

func TestConsumeMergeRecord_WrongTarget(t *testing.T) {
	s, userA, userB := setupMergeFixture(t)
	ctx := context.Background()

	rec := &store.MergeRecord{
		ID:         uuid.New(),
		TokenHash:  hashToken("wrong-target"),
		SourceUser: userB.ID,
		TargetUser: userA.ID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	_ = s.CreateMergeRecord(ctx, rec)

	// Try consuming with the wrong target user.
	wrongID := uuid.New()
	_, err := s.ConsumeMergeRecord(ctx, hashToken("wrong-target"), wrongID)
	if !errors.Is(err, store.ErrMergeTokenExpired) {
		t.Fatalf("expected ErrMergeTokenExpired for wrong target, got %v", err)
	}
}

func TestMergeUsers_ProfileSmartMerge(t *testing.T) {
	s := mock.New()
	ctx := context.Background()

	target := &store.User{ID: uuid.New(), Email: "keep@example.com", DisplayName: "Keep"}
	source := &store.User{ID: uuid.New(), Email: "discard@example.com", Phone: "+999", AvatarURL: "https://new-avatar"}
	s.SeedUser(target)
	s.SeedUser(source)

	_ = s.CreateOAuthAccount(ctx, &store.OAuthAccount{
		Provider: "google", ProviderUserID: "g-src", UserID: source.ID,
	})

	if err := s.MergeUsers(ctx, target.ID, source.ID); err != nil {
		t.Fatal(err)
	}

	merged, _ := s.GetUserByID(ctx, target.ID)
	if merged.Email != "keep@example.com" {
		t.Fatalf("email should be kept, got %q", merged.Email)
	}
	if merged.Phone != "+999" {
		t.Fatalf("phone should be filled from source, got %q", merged.Phone)
	}
	if merged.DisplayName != "Keep" {
		t.Fatalf("display_name should be kept, got %q", merged.DisplayName)
	}
	if merged.AvatarURL != "https://new-avatar" {
		t.Fatalf("avatar_url should be filled from source, got %q", merged.AvatarURL)
	}
}
