// Package config handles loading and validating csar-auth configuration.
package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level csar-auth configuration.
type Config struct {
	ListenAddr  string         `yaml:"listen_addr"`
	BaseURL     string         `yaml:"base_url"`
	FrontendURL string         `yaml:"frontend_url"`
	Database    DatabaseConfig `yaml:"database"`
	JWT         JWTConfig      `yaml:"jwt"`
	OAuth       OAuthConfig    `yaml:"oauth"`
	Cookie      CookieConfig   `yaml:"cookie"`
	Redis       *RedisConfig   `yaml:"redis,omitempty"`
	STS         STSConfig      `yaml:"sts,omitempty"`
}

// STSConfig controls the Security Token Service for service-to-service auth.
type STSConfig struct {
	Enabled         bool                              `yaml:"enabled"`
	AssertionMaxAge Duration                          `yaml:"assertion_max_age"` // default: "5m"
	ServiceAccounts map[string]ServiceAccountConfig   `yaml:"service_accounts"`
}

// ServiceAccountConfig defines a single service account for STS token exchange.
type ServiceAccountConfig struct {
	PublicKeyFile     string   `yaml:"public_key_file"`      // path to PEM public key
	PublicKey         string   `yaml:"public_key"`           // OR inline PEM
	AllowedAudiences  []string `yaml:"allowed_audiences"`    // e.g. ["balance"]
	AllowAllAudiences bool     `yaml:"allow_all_audiences"`  // if true, audience param is optional and defaults to all allowed
	TokenTTL          Duration `yaml:"token_ttl"`            // default: inherits jwt.ttl
}

// DatabaseConfig selects the storage backend.
type DatabaseConfig struct {
	Driver string `yaml:"driver"` // "postgres" (future: "mongodb", "ydb", "sqlite")
	DSN    string `yaml:"dsn"`
}

// JWTConfig controls token signing and key management.
type JWTConfig struct {
	PrivateKeyFile string   `yaml:"private_key_file"`
	PublicKeyFile  string   `yaml:"public_key_file"`
	Algorithm      string   `yaml:"algorithm"` // "RS256" or "EdDSA"
	Issuer         string   `yaml:"issuer"`
	Audience       string   `yaml:"audience"`
	TTL            Duration `yaml:"ttl"`
	AutoGenerate   bool     `yaml:"auto_generate"`
	KeyDir         string   `yaml:"key_dir"`
}

// OAuthConfig configures Goth providers and the state cookie secret.
type OAuthConfig struct {
	SessionSecret string           `yaml:"session_secret"`
	Providers     []ProviderConfig `yaml:"providers"`
}

// ProviderConfig defines a single OAuth provider.
type ProviderConfig struct {
	Name         string   `yaml:"name"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	CallbackURL  string   `yaml:"callback_url"`
	Scopes       []string `yaml:"scopes"`
}

// CookieConfig controls the session cookie parameters.
type CookieConfig struct {
	Name     string `yaml:"name"`
	Domain   string `yaml:"domain"`
	Secure   bool   `yaml:"secure"`
	SameSite string `yaml:"same_site"` // "lax", "strict", "none"
}

// RedisConfig configures an optional Redis connection.
type RedisConfig struct {
	Address  string `yaml:"address"`  // e.g. "localhost:6379"
	Password string `yaml:"password"` // optional AUTH password
	DB       int    `yaml:"db"`       // database number, default 0
}

// Duration wraps time.Duration for YAML unmarshalling from strings like "24h".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// Load reads and parses a YAML config file, expanding environment variables.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return LoadFromBytes(data)
}

// LoadFromBytes parses raw YAML bytes into a Config, expanding environment
// variables, applying defaults, and validating. This is the entry point used
// by both file-based and S3/HTTP config sources.
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	expandEnvInConfig(&cfg)

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8081"
	}
	if cfg.JWT.Algorithm == "" {
		cfg.JWT.Algorithm = "RS256"
	}
	if cfg.JWT.TTL == 0 {
		cfg.JWT.TTL = Duration(24 * time.Hour)
	}
	if cfg.JWT.KeyDir == "" {
		cfg.JWT.KeyDir = "./keys"
	}
	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "csar_session"
	}
	if cfg.Cookie.SameSite == "" {
		cfg.Cookie.SameSite = "lax"
	}
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "postgres"
	}
	if cfg.STS.Enabled && cfg.STS.AssertionMaxAge == 0 {
		cfg.STS.AssertionMaxAge = Duration(5 * time.Minute)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}
	if c.OAuth.SessionSecret == "" {
		return fmt.Errorf("oauth.session_secret is required")
	}
	if len(c.OAuth.Providers) == 0 {
		return fmt.Errorf("at least one oauth provider is required")
	}
	for i, p := range c.OAuth.Providers {
		if p.Name == "" {
			return fmt.Errorf("oauth.providers[%d].name is required", i)
		}
		if p.ClientID == "" {
			return fmt.Errorf("oauth.providers[%d].client_id is required", i)
		}
		if p.ClientSecret == "" {
			return fmt.Errorf("oauth.providers[%d].client_secret is required", i)
		}
	}
	switch c.JWT.Algorithm {
	case "RS256", "EdDSA":
	default:
		return fmt.Errorf("jwt.algorithm must be RS256 or EdDSA, got %q", c.JWT.Algorithm)
	}

	// Validate STS config when enabled.
	if c.STS.Enabled {
		if len(c.STS.ServiceAccounts) == 0 {
			return fmt.Errorf("sts.service_accounts must not be empty when STS is enabled")
		}
		for name, sa := range c.STS.ServiceAccounts {
			if sa.PublicKeyFile == "" && sa.PublicKey == "" {
				return fmt.Errorf("sts.service_accounts[%s]: public_key_file or public_key is required", name)
			}
			if sa.PublicKeyFile != "" && sa.PublicKey != "" {
				return fmt.Errorf("sts.service_accounts[%s]: specify only one of public_key_file or public_key", name)
			}
			if len(sa.AllowedAudiences) == 0 {
				return fmt.Errorf("sts.service_accounts[%s].allowed_audiences must not be empty", name)
			}
		}
	}

	return nil
}

var envVarRe = regexp.MustCompile(`\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

func expandEnv(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		// ${VAR} form
		if len(match) > 3 && match[0] == '$' && match[1] == '{' {
			name := match[2 : len(match)-1]
			if v, ok := os.LookupEnv(name); ok {
				return v
			}
			return match // leave unexpanded if not set
		}
		// $VAR form
		name := match[1:]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return match
	})
}

func expandEnvInConfig(cfg *Config) {
	cfg.ListenAddr = expandEnv(cfg.ListenAddr)
	cfg.BaseURL = expandEnv(cfg.BaseURL)
	cfg.FrontendURL = expandEnv(cfg.FrontendURL)
	cfg.Database.DSN = expandEnv(cfg.Database.DSN)
	cfg.JWT.PrivateKeyFile = expandEnv(cfg.JWT.PrivateKeyFile)
	cfg.JWT.PublicKeyFile = expandEnv(cfg.JWT.PublicKeyFile)
	cfg.JWT.Issuer = expandEnv(cfg.JWT.Issuer)
	cfg.JWT.Audience = expandEnv(cfg.JWT.Audience)
	cfg.JWT.KeyDir = expandEnv(cfg.JWT.KeyDir)
	cfg.OAuth.SessionSecret = expandEnv(cfg.OAuth.SessionSecret)
	cfg.Cookie.Domain = expandEnv(cfg.Cookie.Domain)

	for i := range cfg.OAuth.Providers {
		cfg.OAuth.Providers[i].ClientID = expandEnv(cfg.OAuth.Providers[i].ClientID)
		cfg.OAuth.Providers[i].ClientSecret = expandEnv(cfg.OAuth.Providers[i].ClientSecret)
		cfg.OAuth.Providers[i].CallbackURL = expandEnv(cfg.OAuth.Providers[i].CallbackURL)
	}

	for name, sa := range cfg.STS.ServiceAccounts {
		sa.PublicKeyFile = expandEnv(sa.PublicKeyFile)
		sa.PublicKey = expandEnv(sa.PublicKey)
		cfg.STS.ServiceAccounts[name] = sa
	}

	if cfg.Redis != nil {
		cfg.Redis.Address = expandEnv(cfg.Redis.Address)
		cfg.Redis.Password = expandEnv(cfg.Redis.Password)
	}
}
