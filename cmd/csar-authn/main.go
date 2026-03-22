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
	"time"

	"go.opentelemetry.io/otel"

	"github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/configload"
	"github.com/ledatu/csar-core/configsource"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/health"
	"github.com/ledatu/csar-core/httpmiddleware"
	"github.com/ledatu/csar-core/httpserver"
	"github.com/ledatu/csar-core/logutil"
	"github.com/ledatu/csar-core/observe"
	"github.com/ledatu/csar-core/tlsx"

	"github.com/ledatu/csar-authn/internal/config"
	"github.com/ledatu/csar-authn/internal/handler"
	"github.com/ledatu/csar-authn/internal/oauth"
	"github.com/ledatu/csar-authn/internal/session"
	"github.com/ledatu/csar-authn/internal/store"
	"github.com/ledatu/csar-authn/internal/store/postgres"
	"github.com/ledatu/csar-authn/internal/sts"

	"github.com/redis/go-redis/v9"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	sf := configload.NewSourceFlags()
	sf.RegisterFlags(flag.CommandLine)

	metricsAddr := ""
	otlpEndpoint := ""
	otlpInsecure := false
	flag.StringVar(&metricsAddr, "metrics-addr", metricsAddr, "Prometheus metrics listen address (empty to disable)")
	flag.StringVar(&otlpEndpoint, "otlp-endpoint", otlpEndpoint, "OTLP gRPC endpoint for tracing (empty to disable)")
	flag.BoolVar(&otlpInsecure, "otlp-insecure", otlpInsecure, "use insecure connection for OTLP")
	flag.Parse()

	inner := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(logutil.NewRedactingHandler(inner))

	if err := run(sf, metricsAddr, otlpEndpoint, otlpInsecure, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(
	sf *configload.SourceFlags,
	metricsAddr, otlpEndpoint string,
	otlpInsecure bool,
	logger *slog.Logger,
) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srcParams := sf.SourceParams()
	cfg, err := configload.LoadInitial(ctx, &srcParams, logger, config.LoadFromBytes)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	logger.Info("config loaded",
		"listen_addr", cfg.ListenAddr,
		"database_driver", cfg.Database.Driver,
		"providers", len(cfg.OAuth.Providers),
	)

	// Use config-level metrics_addr if CLI flag is empty.
	if metricsAddr == "" {
		metricsAddr = cfg.MetricsAddr
	}

	// --- Observability ---
	tp, err := observe.InitTracer(ctx, observe.TraceConfig{
		ServiceName:    "csar-authn",
		ServiceVersion: Version,
		Endpoint:       otlpEndpoint,
		Insecure:       otlpInsecure,
	})
	if err != nil {
		return fmt.Errorf("initializing tracer: %w", err)
	}
	defer func() { _ = tp.Close() }()

	reg := observe.NewRegistry()

	// --- Database ---
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
	defer func() { _ = st.Close() }()

	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	logger.Info("migrations applied")

	// --- JWT keys ---
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

	sessMgr := session.NewSessionManager(
		st,
		logger,
		cfg.Session.MaxAge.Std(),
		cfg.Session.IdleTimeout.Std(),
		cfg.Session.TouchThreshold.Std(),
	)
	logger.Info("session manager initialized",
		"max_age", cfg.Session.MaxAge.Std(),
		"idle_timeout", cfg.Session.IdleTimeout.Std(),
		"touch_threshold", cfg.Session.TouchThreshold.Std(),
	)

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

	// Optional authz client for permissions endpoints.
	var authzClient *handler.AuthzClient
	if cfg.Authz.Enabled {
		tokenSrc := handler.NewServiceTokenSource(sessionMgr, "svc:csar-authn", []string{cfg.JWT.Audience}, 5*time.Minute)
		authzClient, err = handler.NewAuthzClient(cfg.Authz.Endpoint, cfg.Authz.TLS, tokenSrc, logger.With("component", "authz-client"))
		if err != nil {
			return fmt.Errorf("connecting to authz service: %w", err)
		}
		defer func() { _ = authzClient.Close() }()
		logger.Info("authz client connected", "endpoint", cfg.Authz.Endpoint)
	}

	// --- Audit store ---
	var auditStore audit.Store
	if pgStore, ok := st.(*postgres.Store); ok {
		pgAudit := audit.NewPostgresStore(pgStore.Pool(), logger.With("component", "audit"))
		if err := pgAudit.Migrate(ctx); err != nil {
			return fmt.Errorf("running audit migrations: %w", err)
		}
		auditStore = pgAudit
		logger.Info("audit store initialized (shared postgres pool)")
	}

	// --- Routes ---
	mux := http.NewServeMux()
	h := handler.New(st, sessionMgr, sessMgr, oauthMgr, stsHandler, authzClient, auditStore, logger, cfg)
	h.RegisterRoutes(mux)

	// Health and readiness endpoints.
	mux.Handle("GET /health", health.Handler(Version))
	rc := health.NewReadinessChecker(Version, true)
	if pgStore, ok := st.(*postgres.Store); ok {
		pool := pgStore.Pool()
		rc.Register("postgres", func() health.CheckStatus {
			if err := pool.Ping(context.Background()); err != nil {
				return health.CheckStatus{Status: "fail", Detail: err.Error()}
			}
			return health.CheckStatus{Status: "ok"}
		})
	}
	mux.Handle("GET /readiness", rc.Handler())

	// --- Session cleanup ---
	go func() {
		ticker := time.NewTicker(cfg.Session.CleanupInterval.Std())
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n, err := st.DeleteExpiredSessions(ctx)
				if err != nil {
					logger.Error("session cleanup failed", "error", err)
				} else if n > 0 {
					logger.Info("session cleanup", "deleted", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// --- Merge authz reconciler ---
	go h.RunMergeAuthzReconciler(ctx, 60*time.Second)

	// --- Middleware ---
	stack := httpmiddleware.Chain(
		httpmiddleware.RequestID,
		httpmiddleware.AccessLog(logger),
		httpmiddleware.Recover(logger),
		httpmiddleware.MaxBodySize(1<<20),
		gatewayctx.Middleware,
		observe.HTTPMiddleware(otel.GetTracerProvider(), "csar-authn"),
	)
	appHandler := stack(mux)

	// --- Config watcher ---
	if interval := sf.ParseRefreshInterval(); interval > 0 {
		src, err := configsource.BuildSource(&srcParams, logger)
		if err != nil {
			return fmt.Errorf("building config source for watcher: %w", err)
		}

		watchLogger := logger.With("component", "config_watcher")
		applyFn := func(applyCtx context.Context, data []byte) (bool, error) {
			newCfg, err := config.LoadFromBytes(data)
			if err != nil {
				return false, err
			}

			if err := oauthMgr.Reload(newCfg); err != nil {
				return false, fmt.Errorf("reloading oauth providers: %w", err)
			}

			if stsHandler != nil {
				stsHandler.SetAssertionMaxAge(newCfg.STS.AssertionMaxAge.Std())
				if err := stsHandler.Reload(applyCtx); err != nil {
					return false, fmt.Errorf("reloading STS accounts: %w", err)
				}
			}

			h.SetConfig(newCfg)

			watchLogger.Info("config reloaded",
				"providers", len(newCfg.OAuth.Providers),
			)
			return true, nil
		}

		watcher := configsource.NewConfigWatcher(src, applyFn, watchLogger, sf.WatcherOptions()...)
		go watcher.RunPeriodicWatch(ctx, interval)
		logger.Info("config watcher started", "interval", interval)
	}

	// --- Metrics sidecar ---
	if metricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", observe.MetricsHandler(reg))
		metricsMux.Handle("/health", health.Handler(Version))
		metricsMux.Handle("/readiness", rc.Handler())

		metricsSrv, err := httpserver.New(&httpserver.Config{
			Addr:         metricsAddr,
			Handler:      metricsMux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}, logger.With("component", "metrics"))
		if err != nil {
			return fmt.Errorf("creating metrics server: %w", err)
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil {
				logger.Error("metrics server error", "error", err)
			}
		}()
		logger.Info("metrics server started", "addr", metricsAddr)
	}

	// --- Main HTTP server ---
	var tlsCfg *tlsx.ServerConfig
	if cfg.TLS.IsEnabled() {
		tlsCfg = &tlsx.ServerConfig{
			CertFile:     cfg.TLS.CertFile,
			KeyFile:      cfg.TLS.KeyFile,
			ClientCAFile: cfg.TLS.ClientCAFile,
			MinVersion:   cfg.TLS.MinVersion,
		}
	}

	srv, err := httpserver.New(&httpserver.Config{
		Addr:    cfg.ListenAddr,
		Handler: appHandler,
		TLS:     tlsCfg,
	}, logger)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	return srv.Run(ctx)
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

	var bootstrap []sts.BootstrapAccount
	for _, ba := range cfg.STS.Accounts {
		bootstrap = append(bootstrap, sts.BootstrapAccount{
			Name:              ba.Name,
			PublicKeyPEM:      ba.PublicKeyPEM,
			AllowedAudiences:  ba.AllowedAudiences,
			AllowAllAudiences: ba.AllowAllAudiences,
			TokenTTL:          ba.TokenTTL.Std(),
		})
	}

	stsHandler, err := sts.New(
		ctx,
		st,
		bootstrap,
		cfg.STS.AssertionMaxAge.Std(),
		cfg.JWT.TTL.Std(),
		cfg.JWT.Issuer,
		sessionMgr,
		replayStore,
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("initializing STS: %w", err)
	}
	logger.Info("STS enabled")
	return stsHandler, nil
}
