// csar-authn is a standalone OAuth authentication service.
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

	"github.com/Ledatu/csar-authn/internal/config"
	"github.com/Ledatu/csar-authn/internal/configsource"
	"github.com/Ledatu/csar-authn/internal/handler"
	"github.com/Ledatu/csar-authn/internal/oauth"
	"github.com/Ledatu/csar-authn/internal/session"
	"github.com/Ledatu/csar-authn/internal/store"
	"github.com/Ledatu/csar-authn/internal/store/postgres"
	"github.com/Ledatu/csar-authn/internal/sts"

	"github.com/redis/go-redis/v9"
)

func main() {
	csrcParams := parseFlags()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if err := run(csrcParams, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func parseFlags() configsource.SourceParams {
	p := configsource.SourceParams{
		Source:          envOrDefault("CONFIG_SOURCE", "file"),
		File:            envOrDefault("CONFIG_FILE", "config.yaml"),
		S3Bucket:        envOrDefault("CONFIG_S3_BUCKET", ""),
		S3Key:           envOrDefault("CONFIG_S3_KEY", "config.yaml"),
		S3Endpoint:      envOrDefault("CONFIG_S3_ENDPOINT", "https://storage.yandexcloud.net"),
		S3Region:        envOrDefault("CONFIG_S3_REGION", "ru-central1"),
		S3AuthMode:      envOrDefault("CONFIG_S3_AUTH_MODE", "static"),
		S3AccessKeyID:   envOrDefault("CONFIG_S3_ACCESS_KEY_ID", ""),
		S3SecretKey:     envOrDefault("CONFIG_S3_SECRET_ACCESS_KEY", ""),
		S3IAMToken:      envOrDefault("CONFIG_S3_IAM_TOKEN", ""),
		S3OAuthToken:    envOrDefault("CONFIG_S3_OAUTH_TOKEN", ""),
		S3SAKeyFile:     envOrDefault("CONFIG_S3_SA_KEY_FILE", ""),
		RefreshInterval: envOrDefault("CONFIG_REFRESH_INTERVAL", "0"),
	}

	flag.StringVar(&p.Source, "config-source", p.Source, `config source: "file" or "s3"`)
	flag.StringVar(&p.File, "config", p.File, "path to config file (file source)")
	flag.StringVar(&p.S3Bucket, "config-s3-bucket", p.S3Bucket, "S3 bucket for config")
	flag.StringVar(&p.S3Key, "config-s3-key", p.S3Key, "S3 object key for config")
	flag.StringVar(&p.S3Endpoint, "config-s3-endpoint", p.S3Endpoint, "S3 endpoint")
	flag.StringVar(&p.S3Region, "config-s3-region", p.S3Region, "S3 region")
	flag.StringVar(&p.S3AuthMode, "config-s3-auth-mode", p.S3AuthMode, "S3 auth mode")
	flag.StringVar(&p.S3AccessKeyID, "config-s3-access-key-id", p.S3AccessKeyID, "S3 access key ID")
	flag.StringVar(&p.S3SecretKey, "config-s3-secret-access-key", p.S3SecretKey, "S3 secret access key")
	flag.StringVar(&p.S3IAMToken, "config-s3-iam-token", p.S3IAMToken, "S3 IAM token")
	flag.StringVar(&p.S3OAuthToken, "config-s3-oauth-token", p.S3OAuthToken, "S3 OAuth token")
	flag.StringVar(&p.S3SAKeyFile, "config-s3-sa-key-file", p.S3SAKeyFile, "S3 service account key file")
	flag.StringVar(&p.RefreshInterval, "config-refresh-interval", p.RefreshInterval, "config polling interval (e.g. 60s); 0 disables")

	flag.Parse()
	return p
}

func run(p configsource.SourceParams, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := configsource.LoadInitial(ctx, p, logger)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	logger.Info("config loaded",
		"listen_addr", cfg.ListenAddr,
		"database_driver", cfg.Database.Driver,
		"providers", len(cfg.OAuth.Providers),
	)

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

	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	logger.Info("migrations applied")

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

	sessionMgr := session.NewManager(keys, cfg.JWT)

	oauthMgr, err := oauth.NewManager(cfg, logger)
	if err != nil {
		return fmt.Errorf("initializing oauth: %w", err)
	}

	var stsHandler *sts.Handler
	if cfg.STS.Enabled {
		stsHandler, err = initSTS(ctx, cfg, st, sessionMgr, logger)
		if err != nil {
			return err
		}
	}

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

	if interval := parseInterval(p.RefreshInterval); interval > 0 {
		src, err := configsource.BuildSource(p, logger)
		if err != nil {
			return fmt.Errorf("building config source for watcher: %w", err)
		}
		watcher := configsource.NewConfigWatcher(
			src,
			logger.With("component", "config_watcher"),
			configsource.WithHashPolicy(configsource.HashTOFU),
		)
		go watcher.RunPeriodicWatch(ctx, interval)
		logger.Info("config watcher started (validation-only; config changes require restart)", "interval", interval)
	}

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

func initSTS(
	ctx context.Context,
	cfg *config.Config,
	st store.Store,
	sessionMgr *session.Manager,
	logger *slog.Logger,
) (*sts.Handler, error) {
	var replayStore sts.ReplayStore
	if cfg.Redis != nil && cfg.Redis.Address != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Address,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("connecting to redis: %w", err)
		}
		replayStore = sts.NewRedisReplayStore(redisClient)
		logger.Info("STS replay protection: redis", "address", cfg.Redis.Address)
	} else if pgStore, ok := st.(*postgres.Store); ok {
		replayStore = sts.NewPostgresReplayStore(pgStore.Pool())
		logger.Info("STS replay protection: postgres")
	}

	stsHandler, err := sts.New(cfg.STS, cfg.JWT, sessionMgr, replayStore, logger)
	if err != nil {
		return nil, fmt.Errorf("initializing STS: %w", err)
	}
	logger.Info("STS enabled", "service_accounts", len(cfg.STS.ServiceAccounts))
	return stsHandler, nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseInterval(s string) time.Duration {
	if s == "" || s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
