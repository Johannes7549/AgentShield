package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentshield/agentshield/runtime/gateway/internal/authz"
	"github.com/agentshield/agentshield/runtime/gateway/internal/config"
	"github.com/agentshield/agentshield/runtime/gateway/internal/httpserver"
	"github.com/agentshield/agentshield/runtime/gateway/internal/limits"
	"github.com/agentshield/agentshield/runtime/gateway/internal/nonce"
	"github.com/agentshield/agentshield/runtime/gateway/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("configuration", "error", err.Error())
		os.Exit(1)
	}

	var authorizer httpserver.Authorizer
	var ready func(context.Context) error
	if cfg.DatabaseURL != "" && cfg.RedisURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pool, err := store.Open(ctx, cfg.DatabaseURL)
		cancel()
		if err != nil {
			slog.Error("database", "error", "configuration rejected")
			os.Exit(1)
		}
		defer pool.Close()
		client, err := nonce.Open(cfg.RedisURL)
		if err != nil {
			slog.Error("redis", "error", "configuration rejected")
			os.Exit(1)
		}
		defer client.Close()
		postgres := store.New(pool)
		authorizer = &authz.Service{
			Directory: store.Directory{DB: postgres},
			Policies:  store.PolicyReader{DB: postgres},
			Store:     store.Decisions{DB: postgres},
			Nonces:    nonce.New(client),
			Limits:    limits.NewLimiter(client),
			Breaker:   limits.NewBreaker(client),
		}
		ready = func(ctx context.Context) error {
			if err := pool.Ping(ctx); err != nil {
				return errors.New("database is unavailable")
			}
			if err := client.Ping(ctx).Err(); err != nil {
				return errors.New("redis is unavailable")
			}
			return nil
		}
	}

	server := httpserver.New(cfg, authorizer, ready)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "service", config.ServiceName, "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		slog.Error("server", "error", err.Error())
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "error", err.Error())
		os.Exit(1)
	}
}
