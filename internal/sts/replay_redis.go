package sts

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisReplayStore is a ReplayStore backed by Redis.
// It uses SET NX with a TTL derived from the assertion's exp, so keys
// auto-expire and no background cleanup goroutine is needed.
type RedisReplayStore struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisReplayStore creates a Redis-backed replay store.
// The Redis client lifecycle is owned by the caller.
func NewRedisReplayStore(client *redis.Client) *RedisReplayStore {
	return &RedisReplayStore{client: client, keyPrefix: "sts:jti:"}
}

// CheckAndRecord atomically checks if the (issuer, jti) pair was already seen
// and records it if not. Returns true when the pair already existed (replay detected).
func (s *RedisReplayStore) CheckAndRecord(ctx context.Context, issuer, jti string, exp time.Time) (bool, error) {
	ttl := time.Until(exp)
	if ttl <= 0 {
		ttl = time.Second
	}
	ok, err := s.client.SetNX(ctx, s.keyPrefix+issuer+":"+jti, "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return !ok, nil
}
