package limits

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestTokensAndThresholds(t *testing.T) {
	if Tokens(0) != 1 || Tokens(1) != 1 || Tokens(4) != 1 || Tokens(5) != 2 {
		t.Fatalf("tokens = %d %d %d %d", Tokens(0), Tokens(1), Tokens(4), Tokens(5))
	}
	if err := Decide(MaxRequests, MaxToolCalls, MaxTokens); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Decide(MaxRequests+1, 1, 1), ErrRequests) {
		t.Fatal("requests")
	}
	if !errors.Is(Decide(1, MaxToolCalls+1, 1), ErrTool) {
		t.Fatal("tool")
	}
	if !errors.Is(Decide(1, 1, MaxTokens+1), ErrBudget) {
		t.Fatal("budget")
	}
}

func TestRedisLimitsAndCircuit(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:6379",
		DialTimeout: 200 * time.Millisecond,
		ReadTimeout: 200 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("redis is not available")
	}
	defer client.Close()

	agentID := "11111111-1111-4111-8111-111111111199"
	tool := "sample.echo"
	keys := []string{
		"agentshield:v1:rate:" + agentID,
		"agentshield:v1:tool:" + agentID + ":" + tool,
		"agentshield:v1:tokens:" + agentID,
		openKey(agentID, tool),
		failKey(agentID, tool),
	}
	t.Cleanup(func() {
		_ = client.Del(context.Background(), keys...).Err()
	})
	if err := client.Del(ctx, keys...).Err(); err != nil {
		t.Fatal(err)
	}

	limiter := NewLimiter(client)
	if err := limiter.Take(ctx, agentID, tool, 1); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, "agentshield:v1:rate:"+agentID, MaxRequests, Window).Err(); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Take(ctx, agentID, tool, 1); !errors.Is(err, ErrRequests) {
		t.Fatalf("rate = %v", err)
	}

	breaker := NewBreaker(client)
	if err := breaker.Allow(ctx, agentID, tool); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < FailureThreshold; i++ {
		if err := breaker.Failure(ctx, agentID, tool); err != nil {
			t.Fatal(err)
		}
	}
	if err := breaker.Allow(ctx, agentID, tool); !errors.Is(err, ErrOpen) {
		t.Fatalf("open = %v", err)
	}
	if err := client.Del(ctx, openKey(agentID, tool)).Err(); err != nil {
		t.Fatal(err)
	}
	if err := breaker.Success(ctx, agentID, tool); err != nil {
		t.Fatal(err)
	}
	if err := breaker.Allow(ctx, agentID, tool); err != nil {
		t.Fatal(err)
	}
}
