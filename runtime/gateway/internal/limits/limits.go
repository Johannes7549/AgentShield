// Package limits enforces request rate, tool-call rate, and a byte-derived
// token budget. It also opens a short circuit after repeated adapter failures.
// None of these controls consult a model.
package limits

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	Window            = 60 * time.Second
	OpenFor           = 30 * time.Second
	MaxRequests       = 60
	MaxToolCalls      = 30
	MaxTokens         = 100_000
	FailureThreshold  = 5
	ArgumentByteLimit = 4096
	DenyBurst         = 5
	AdapterTimeout    = 2 * time.Second
)

var (
	ErrRequests    = errors.New("request rate limit exceeded")
	ErrTool        = errors.New("tool call limit exceeded")
	ErrBudget      = errors.New("token budget exceeded")
	ErrUnavailable = errors.New("limit store is unavailable")
	ErrOpen        = errors.New("circuit open")
)

// Tokens estimates a budget charge from the raw body length. It is not a
// model tokenizer. Four bytes count as one token, and an empty body counts
// as one so a call cannot bypass the budget.
func Tokens(bodyLength int) int {
	if bodyLength < 1 {
		return 1
	}
	return (bodyLength + 3) / 4
}

// Decide reports which threshold a set of counters crossed. The Redis script
// uses the same comparisons.
func Decide(requests int, tools int, tokens int) error {
	if requests > MaxRequests {
		return ErrRequests
	}
	if tools > MaxToolCalls {
		return ErrTool
	}
	if tokens > MaxTokens {
		return ErrBudget
	}
	return nil
}

type Limiter struct {
	client *redis.Client
}

func NewLimiter(client *redis.Client) *Limiter {
	return &Limiter{client: client}
}

var takeScript = redis.NewScript(`
local requests = redis.call("INCR", KEYS[1])
if requests == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local tools = redis.call("INCR", KEYS[2])
if tools == 1 then
  redis.call("PEXPIRE", KEYS[2], ARGV[1])
end
local tokens = redis.call("INCRBY", KEYS[3], ARGV[2])
if tokens == tonumber(ARGV[2]) then
  redis.call("PEXPIRE", KEYS[3], ARGV[1])
end
if requests > tonumber(ARGV[3]) then
  return "requests"
end
if tools > tonumber(ARGV[4]) then
  return "tool"
end
if tokens > tonumber(ARGV[5]) then
  return "tokens"
end
return "ok"
`)

func (l *Limiter) Take(ctx context.Context, agentID string, tool string, tokens int) error {
	if l == nil || l.client == nil {
		return ErrUnavailable
	}
	if tokens < 1 {
		tokens = 1
	}
	result, err := takeScript.Run(ctx, l.client, []string{
		"agentshield:v1:rate:" + agentID,
		"agentshield:v1:tool:" + agentID + ":" + tool,
		"agentshield:v1:tokens:" + agentID,
	}, strconv.FormatInt(Window.Milliseconds(), 10), tokens, MaxRequests, MaxToolCalls, MaxTokens).Text()
	if err != nil {
		return ErrUnavailable
	}
	switch result {
	case "ok":
		return nil
	case "requests":
		return ErrRequests
	case "tool":
		return ErrTool
	case "tokens":
		return ErrBudget
	default:
		return ErrUnavailable
	}
}

type Breaker struct {
	client *redis.Client
}

func NewBreaker(client *redis.Client) *Breaker {
	return &Breaker{client: client}
}

func (b *Breaker) Allow(ctx context.Context, organizationID string, tool string) error {
	if b == nil || b.client == nil {
		return ErrUnavailable
	}
	open, err := b.client.Exists(ctx, openKey(organizationID, tool)).Result()
	if err != nil {
		return ErrUnavailable
	}
	if open > 0 {
		return ErrOpen
	}
	return nil
}

func (b *Breaker) Failure(ctx context.Context, organizationID string, tool string) error {
	if b == nil || b.client == nil {
		return ErrUnavailable
	}
	count, err := b.client.Incr(ctx, failKey(organizationID, tool)).Result()
	if err != nil {
		return ErrUnavailable
	}
	if count == 1 {
		if err := b.client.Expire(ctx, failKey(organizationID, tool), Window).Err(); err != nil {
			return ErrUnavailable
		}
	}
	if count >= FailureThreshold {
		if err := b.client.Set(ctx, openKey(organizationID, tool), "1", OpenFor).Err(); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func (b *Breaker) Success(ctx context.Context, organizationID string, tool string) error {
	if b == nil || b.client == nil {
		return ErrUnavailable
	}
	if err := b.client.Del(ctx, failKey(organizationID, tool)).Err(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func openKey(organizationID string, tool string) string {
	return "agentshield:v1:circuit:" + organizationID + ":" + tool
}

func failKey(organizationID string, tool string) string {
	return "agentshield:v1:circuit-fail:" + organizationID + ":" + tool
}
