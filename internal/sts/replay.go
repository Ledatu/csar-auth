package sts

import (
	"context"
	"sync"
	"time"
)

// ReplayStore tracks JTI values to prevent assertion replay attacks.
// Implementations must be safe for concurrent use.
type ReplayStore interface {
	// CheckAndRecord returns true if the JTI was already seen (replay).
	// If not previously seen, records it with the given expiration time.
	CheckAndRecord(ctx context.Context, jti string, exp time.Time) (bool, error)
}

// memoryReplayStore is an in-memory ReplayStore for single-instance deployments
// or as a fallback when no durable store is configured.
type memoryReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
	cancel  context.CancelFunc
}

// NewMemoryReplayStore creates an in-memory replay store with a background
// cleanup goroutine. Call Stop() to release resources.
func NewMemoryReplayStore() *memoryReplayStore {
	ctx, cancel := context.WithCancel(context.Background())
	s := &memoryReplayStore{
		entries: make(map[string]time.Time),
		cancel:  cancel,
	}
	go s.cleanup(ctx)
	return s
}

func (s *memoryReplayStore) CheckAndRecord(_ context.Context, jti string, exp time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[jti]; exists {
		return true, nil
	}
	s.entries[jti] = exp
	return false, nil
}

// Stop cancels the background cleanup goroutine.
func (s *memoryReplayStore) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *memoryReplayStore) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for jti, exp := range s.entries {
				if now.After(exp) {
					delete(s.entries, jti)
				}
			}
			s.mu.Unlock()
		}
	}
}
