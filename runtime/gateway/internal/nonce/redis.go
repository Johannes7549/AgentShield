package nonce

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const ttl = 130 * time.Second

var ErrReplay = errors.New("nonce already used")

type Store struct {
	client *redis.Client
}

func New(client *redis.Client) *Store {
	return &Store{client: client}
}

func Open(url string) (*redis.Client, error) {
	options, err := redis.ParseURL(url)
	if err != nil {
		return nil, errors.New("REDIS_URL is invalid")
	}
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	return redis.NewClient(options), nil
}

// Reserve stores the nonce for longer than the signature skew window.
// A second reservation of the same agent and nonce is a replay.
func (s *Store) Reserve(ctx context.Context, agentID string, nonce string) error {
	if s == nil || s.client == nil {
		return errors.New("nonce store is not configured")
	}
	key := "agentshield:v1:nonce:" + agentID + ":" + nonce
	ok, err := s.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return errors.New("nonce store is unavailable")
	}
	if !ok {
		return ErrReplay
	}
	return nil
}
