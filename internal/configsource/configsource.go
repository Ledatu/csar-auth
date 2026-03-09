// Package configsource provides config source wiring for csar-auth.
// It re-exports csar-core/configsource types and provides a BuildSource
// factory so that main.go (and any future csar-auth subcommands) stay thin.
package configsource

import (
	"context"
	"fmt"
	"log/slog"

	coresrc "github.com/Ledatu/csar-core/configsource"
	"github.com/Ledatu/csar-core/s3store"
	"github.com/Ledatu/csar-core/secret"
	"github.com/Ledatu/csar-core/ycloud"

	"github.com/Ledatu/csar-auth/internal/config"
)

// Re-export core types for convenience.
type (
	ConfigSource  = coresrc.ConfigSource
	FetchedConfig = coresrc.FetchedConfig
	HashPolicy    = coresrc.HashPolicy

	ConfigWatcher = coresrc.ConfigWatcher
	WatcherOption = coresrc.WatcherOption
	ApplyFunc     = coresrc.ApplyFunc
)

var (
	NewFileSource = coresrc.NewFileSource
	NewS3Source   = coresrc.NewS3Source
	NewHTTPSource = coresrc.NewHTTPSource

	WithHashPolicy = coresrc.WithHashPolicy
	WithPinnedHash = coresrc.WithPinnedHash
)

const (
	HashDisabled = coresrc.HashDisabled
	HashTOFU     = coresrc.HashTOFU
	HashPinned   = coresrc.HashPinned
)

// SourceParams holds the flags/env vars needed to build a ConfigSource.
type SourceParams struct {
	Source          string // "file" or "s3"
	File            string // path for file source
	S3Bucket        string
	S3Key           string
	S3Endpoint      string
	S3Region        string
	S3AuthMode      string
	S3AccessKeyID   string
	S3SecretKey     string
	S3IAMToken      string
	S3OAuthToken    string
	S3SAKeyFile     string
	RefreshInterval string // e.g. "60s"; "0" or "" disables
}

// BuildSource creates a ConfigSource from the given params.
func BuildSource(p SourceParams, logger *slog.Logger) (ConfigSource, error) {
	switch p.Source {
	case "file":
		logger.Info("config source: file", "path", p.File)
		return NewFileSource(p.File), nil

	case "s3":
		if p.S3Bucket == "" {
			return nil, fmt.Errorf("--config-s3-bucket / CONFIG_S3_BUCKET is required for s3 source")
		}
		client, err := s3store.NewClient(s3store.Config{
			Bucket:   p.S3Bucket,
			Endpoint: p.S3Endpoint,
			Region:   p.S3Region,
			Auth: ycloud.AuthConfig{
				AuthMode:        p.S3AuthMode,
				IAMToken:        secret.NewSecret(p.S3IAMToken),
				OAuthToken:      secret.NewSecret(p.S3OAuthToken),
				SAKeyFile:       p.S3SAKeyFile,
				AccessKeyID:     secret.NewSecret(p.S3AccessKeyID),
				SecretAccessKey: secret.NewSecret(p.S3SecretKey),
			},
		}, logger)
		if err != nil {
			return nil, fmt.Errorf("creating S3 client: %w", err)
		}
		logger.Info("config source: s3", "bucket", p.S3Bucket, "key", p.S3Key)
		return NewS3Source(client, p.S3Key), nil

	default:
		return nil, fmt.Errorf("unknown config source %q; supported: file, s3", p.Source)
	}
}

// LoadInitial fetches config from the source once and parses it.
func LoadInitial(ctx context.Context, p SourceParams, logger *slog.Logger) (*config.Config, error) {
	src, err := BuildSource(p, logger)
	if err != nil {
		return nil, err
	}

	fetched, err := src.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching config: %w", err)
	}
	if fetched.Data == nil {
		return nil, fmt.Errorf("config source returned empty data")
	}

	return config.LoadFromBytes(fetched.Data)
}

// NewConfigWatcher creates a ConfigWatcher that validates new config bytes
// via config.LoadFromBytes. Full hot-reload is not yet implemented; the
// ApplyFunc only validates and logs. Returns changed=false because no
// runtime state is modified.
func NewConfigWatcher(
	source ConfigSource,
	logger *slog.Logger,
	opts ...WatcherOption,
) *ConfigWatcher {
	applyFn := func(_ context.Context, data []byte) (bool, error) {
		_, err := config.LoadFromBytes(data)
		if err != nil {
			return false, err
		}
		logger.Info("config refresh: new config validated (hot-reload not yet implemented; restart required to apply changes)")
		return false, nil
	}
	return coresrc.NewConfigWatcher(source, applyFn, logger, opts...)
}
