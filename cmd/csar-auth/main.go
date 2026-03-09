// csar-auth is a standalone OAuth authentication service.
//
// It handles multi-provider OAuth login (via Goth), maps social identities
// to internal user UUIDs, issues JWT session tokens, and exposes a JWKS
// endpoint for the csar router to validate sessions.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Ledatu/csar-auth/internal/config"
	"github.com/Ledatu/csar-auth/internal/handler"
	"github.com/Ledatu/csar-auth/internal/oauth"
	"github.com/Ledatu/csar-auth/internal/session"
	"github.com/Ledatu/csar-auth/internal/store"
	"github.com/Ledatu/csar-auth/internal/store/postgres"
	"github.com/Ledatu/csar-auth/internal/sts"

	"github.com/redis/go-redis/v9"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if err := run(*configPath, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	// Load config.
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	logger.Info("config loaded",
		"listen_addr", cfg.ListenAddr,
		"database_driver", cfg.Database.Driver,
		"providers", len(cfg.OAuth.Providers),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize store.
	var st store.Store
	switch cfg.Database.Driver {
	case "postgres":
		pgStore, err := postgres.New(ctx, cfg.Database.DSN, postgres.WithLogger(logger))
		if err != nil {
			return fmt.Errorf("connecting to postgres: %w", err)
		}
		st = pgStore
	default:
		return fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}
	defer st.Close()

	// Run migrations.
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	logger.Info("migrations applied")

	// Load or generate signing keys.
	keys, err := session.LoadOrGenerateKeys(
		cfg.JWT.Algorithm,
		cfg.JWT.PrivateKeyFile,
		cfg.JWT.PublicKeyFile,
		cfg.JWT.KeyDir,
		cfg.JWT.AutoGenerate,
		logger,
	)
	if err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}
	logger.Info("signing keys ready", "kid", keys.KID, "algorithm", keys.Algorithm)

	// Create session manager.
	sessionMgr := session.NewManager(keys, cfg.JWT)

	// Initialize OAuth providers.
	oauthMgr, err := oauth.NewManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("initializing oauth: %w", err)
	}

	// Initialize STS handler (optional).
	var stsHandler *sts.Handler
	if cfg.STS.Enabled {
		var replayStore sts.ReplayStore
		if cfg.Redis != nil && cfg.Redis.Address != "" {
			redisClient := redis.NewClient(&redis.Options{
				Addr:     cfg.Redis.Address,
				Password: cfg.Redis.Password,
				DB:       cfg.Redis.DB,
			})
			defer redisClient.Close()
			if err := redisClient.Ping(ctx).Err(); err != nil {
				return fmt.Errorf("connecting to redis: %w", err)
			}
			replayStore = sts.NewRedisReplayStore(redisClient)
			logger.Info("STS replay protection: redis", "address", cfg.Redis.Address)
		} else if pgStore, ok := st.(*postgres.Store); ok {
			replayStore = sts.NewPostgresReplayStore(pgStore.Pool())
			logger.Info("STS replay protection: postgres")
		}

		stsHandler, err = sts.New(cfg.STS, cfg.JWT, sessionMgr, replayStore, logger)
		if err != nil {
			return fmt.Errorf("initializing STS: %w", err)
		}
		logger.Info("STS enabled", "service_accounts", len(cfg.STS.ServiceAccounts))
	}

	// Wire HTTP handlers.
	mux := http.NewServeMux()
	h := handler.New(st, sessionMgr, oauthMgr, stsHandler, logger, cfg)
	h.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting server", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig)
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	logger.Info("server stopped")
	return nil
}
