// Package config loads the gateway process configuration.
//
// Production mode is refused until a non-owner database role and row level
// security are in place. Development can authorize tool calls. That is not
// a production deployment.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	ServiceName      = "gateway"
	Version          = "0.1.0"
	DefaultAddr      = "127.0.0.1:8081"
	defaultBodyBytes = 1 << 20
	maximumBodyBytes = 1 << 20
	minimumShutdown  = time.Second
	maximumShutdown  = time.Minute
)

// MaximumBodyBytes is the largest request body the gateway will read.
func MaximumBodyBytes() int64 { return maximumBodyBytes }

type Config struct {
	Addr            string
	Environment     string
	ShutdownTimeout time.Duration
	MaxBodyBytes    int64
	DatabaseURL     string
	RedisURL        string
}

func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	environment := getenv("AGENTSHIELD_ENV")
	if environment == "" {
		environment = "development"
	}
	switch environment {
	case "development", "test":
	case "production":
		if !isAppRoleURL(getenv("DATABASE_URL")) {
			return Config{}, errors.New("production mode requires DATABASE_URL to use the agentshield_app role with row level security")
		}
	default:
		return Config{}, fmt.Errorf("AGENTSHIELD_ENV %q is not supported", environment)
	}

	addr := getenv("GATEWAY_HTTP_ADDR")
	if addr == "" {
		addr = DefaultAddr
	}
	if err := validateAddr(addr); err != nil {
		return Config{}, err
	}

	maxBody := int64(defaultBodyBytes)
	if raw := getenv("GATEWAY_MAX_BODY_BYTES"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return Config{}, errors.New("GATEWAY_MAX_BODY_BYTES must be an integer")
		}
		maxBody = parsed
	}
	if maxBody <= 0 || maxBody > maximumBodyBytes {
		return Config{}, fmt.Errorf("GATEWAY_MAX_BODY_BYTES must be between 1 and %d", maximumBodyBytes)
	}

	shutdown := 10 * time.Second
	if raw := getenv("GATEWAY_SHUTDOWN_TIMEOUT"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, errors.New("GATEWAY_SHUTDOWN_TIMEOUT is invalid")
		}
		shutdown = parsed
	}
	if shutdown < minimumShutdown || shutdown > maximumShutdown {
		return Config{}, errors.New("GATEWAY_SHUTDOWN_TIMEOUT must be between 1s and 1m")
	}

	databaseURL := getenv("DATABASE_URL")
	if databaseURL != "" && !strings.HasPrefix(databaseURL, "postgres://") && !strings.HasPrefix(databaseURL, "postgresql://") {
		return Config{}, errors.New("DATABASE_URL must be a postgres URL")
	}
	redisURL := getenv("REDIS_URL")
	if redisURL != "" && !strings.HasPrefix(redisURL, "redis://") && !strings.HasPrefix(redisURL, "rediss://") {
		return Config{}, errors.New("REDIS_URL must be a redis URL")
	}

	return Config{
		Addr:            addr,
		Environment:     environment,
		ShutdownTimeout: shutdown,
		MaxBodyBytes:    maxBody,
		DatabaseURL:     databaseURL,
		RedisURL:        redisURL,
	}, nil
}

func validateAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("GATEWAY_HTTP_ADDR: %w", err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("GATEWAY_HTTP_ADDR port is invalid")
	}
	return nil
}

func isAppRoleURL(databaseURL string) bool {
	if databaseURL == "" {
		return false
	}
	trimmed := strings.TrimPrefix(databaseURL, "postgres://")
	trimmed = strings.TrimPrefix(trimmed, "postgresql://")
	at := strings.Index(trimmed, "@")
	if at <= 0 {
		return false
	}
	userinfo := trimmed[:at]
	if colon := strings.Index(userinfo, ":"); colon >= 0 {
		userinfo = userinfo[:colon]
	}
	return userinfo == "agentshield_app"
}
