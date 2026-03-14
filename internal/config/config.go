// Package config re-exports the csar-authn configuration schema from
// csar-core/authnconfig. The canonical definitions live in csar-core so
// that csar-helper can validate authn configs without importing this repo.
//
// All type aliases and function wrappers below preserve the existing API
// surface so that the rest of csar-authn needs zero import changes.
package config

import (
	"fmt"
	"os"

	"github.com/ledatu/csar-core/authnconfig"
)

// Re-export all types as aliases so callers keep using config.XYZ.
type (
	Config               = authnconfig.Config
	AuthzConfig          = authnconfig.AuthzConfig
	AuthzTLSConfig       = authnconfig.AuthzTLSConfig
	STSConfig            = authnconfig.STSConfig
	ServiceAccountConfig = authnconfig.ServiceAccountConfig
	DatabaseConfig       = authnconfig.DatabaseConfig
	JWTConfig            = authnconfig.JWTConfig
	OAuthConfig          = authnconfig.OAuthConfig
	ProviderConfig       = authnconfig.ProviderConfig
	CookieConfig         = authnconfig.CookieConfig
	RedisConfig          = authnconfig.RedisConfig
	Duration             = authnconfig.Duration
)

// NewDuration re-exports authnconfig.NewDuration.
var NewDuration = authnconfig.NewDuration

// LoadFromBytes delegates to the canonical implementation in csar-core.
var LoadFromBytes = authnconfig.LoadFromBytes

// Load reads a YAML config file from disk and delegates to LoadFromBytes.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return LoadFromBytes(data)
}
