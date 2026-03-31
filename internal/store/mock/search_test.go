package mock_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/mock"
)

func TestSearchUsers_MatchesAndExcludesMerged(t *testing.T) {
	s := mock.New()

	activeID := uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	mergedInto := uuid.MustParse("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")

	s.SeedUser(&store.User{
		ID:          activeID,
		Email:       "alice@example.com",
		DisplayName: "Alice Example",
		AvatarURL:   "https://example.com/alice.png",
	})
	s.SeedUser(&store.User{
		ID:          uuid.MustParse("ffffffff-ffff-4fff-8fff-ffffffffffff"),
		Email:       "alicia@example.com",
		DisplayName: "Alicia Example",
		MergedInto:  &mergedInto,
	})

	got, err := s.SearchUsers(context.Background(), store.UserSearchParams{
		Query: "alice",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].ID != activeID {
		t.Fatalf("id = %s, want %s", got[0].ID, activeID)
	}
	if got[0].AvatarURL != "https://example.com/alice.png" {
		t.Fatalf("avatar_url = %q", got[0].AvatarURL)
	}
}

func TestSearchUsers_PrioritizesExactID(t *testing.T) {
	s := mock.New()

	exactID := uuid.MustParse("12345678-1234-4234-8234-123456789012")
	s.SeedUser(&store.User{
		ID:          exactID,
		Email:       "person@example.com",
		DisplayName: "Person One",
	})
	s.SeedUser(&store.User{
		ID:          uuid.New(),
		Email:       "12345678-1234-4234-8234-123456789012@example.com",
		DisplayName: "UUID In Email",
	})

	got, err := s.SearchUsers(context.Background(), store.UserSearchParams{
		Query: exactID.String(),
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one result")
	}
	if got[0].ID != exactID {
		t.Fatalf("first result id = %s, want %s", got[0].ID, exactID)
	}
}
