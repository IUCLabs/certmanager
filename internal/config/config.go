package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// AuthMethod selects how certmanager authenticates to Vault.
type AuthMethod string

const (
	AuthMethodAppRole    AuthMethod = "approle"
	AuthMethodKubernetes AuthMethod = "kubernetes"
)

// DefaultJWTPath is the in-cluster service account token location.
const DefaultJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// DefaultTimeout bounds every Vault request; Puppet calls this binary from
// generate() during catalog compilation, so an unbounded request would hang the
// compile forever.
const DefaultTimeout = 30 * time.Second

// defaultPath is overridable at build time with
// -X github.com/IUCLabs/certmanager/internal/config.defaultPath=/some/path
var defaultPath = "/opt/certmanager/config.yaml"

// FallbackPath returns the config path baked in at build time. Puppet writes
// the config there, and it is the only path that resolves under generate(),
// which runs as the puppet user with no usable home directory.
func FallbackPath() string { return defaultPath }

// DefaultPath resolves the config to use when --config was not given:
// $XDG_CONFIG_HOME/certmanager/config.yaml, then
// $HOME/.config/certmanager/config.yaml, then FallbackPath(). The first two
// are only taken when the file is actually there, so an unset or unusable
// HOME lands on the Puppet-managed path instead of a path that cannot exist.
func DefaultPath() string {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		if p := filepath.Join(base, "certmanager", "config.yaml"); isFile(p) {
			return p
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if p := filepath.Join(home, ".config", "certmanager", "config.yaml"); isFile(p) {
			return p
		}
	}
	return defaultPath
}

// Resolve picks the config path for a run: an explicit --config always wins.
func Resolve(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return DefaultPath()
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// Config is the top-level configuration structure.
type Config struct {
	Vault VaultConfig `yaml:"vault"`
}

// VaultConfig holds Vault connection and auth parameters. Only the fields
// relevant to the chosen AuthMethod need to be populated.
type VaultConfig struct {
	Addr       string     `yaml:"addr"`
	AuthMethod AuthMethod `yaml:"auth_method"`
	MountPoint string     `yaml:"mount_point"`
	RoleName   string     `yaml:"role_name"`
	OutputPath string     `yaml:"output_path"`

	RoleID      string `yaml:"role_id"`
	ApprolePath string `yaml:"approle_path"`

	K8sMount string `yaml:"k8s_mount"`
	K8sRole  string `yaml:"k8s_role"`
	JWTPath  string `yaml:"jwt_path"`

	// TLSSkipVerify defaults to true, preserving the Python script's
	// verify=False behaviour until the estate trusts the internal CA.
	TLSSkipVerify *bool `yaml:"tls_skip_verify"`

	// Timeout is a Go duration string (e.g. "30s").
	Timeout string `yaml:"timeout"`
}

// SkipTLSVerify reports whether certificate verification is disabled.
func (v VaultConfig) SkipTLSVerify() bool {
	if v.TLSSkipVerify == nil {
		return true
	}
	return *v.TLSSkipVerify
}

// RequestTimeout returns the configured per-request timeout.
func (v VaultConfig) RequestTimeout() (time.Duration, error) {
	if v.Timeout == "" {
		return DefaultTimeout, nil
	}
	d, err := time.ParseDuration(v.Timeout)
	if err != nil {
		return 0, fmt.Errorf("vault.timeout %q is not a valid duration: %w", v.Timeout, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("vault.timeout %q must be positive", v.Timeout)
	}
	return d, nil
}

// Load reads, parses, defaults and validates the config file at path.
func Load(path string) (*Config, error) {
	cfg, err := parse(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.Vault.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg, nil
}

// LoadCA reads the config for the CA chain path. That endpoint is public, so
// only vault.addr is required: a config carrying no auth method, no role and no
// credentials still loads.
func LoadCA(path string) (*Config, error) {
	cfg, err := parse(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.Vault.ValidateCA(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return cfg, nil
}

func parse(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if cfg.Vault.AuthMethod == "" {
		cfg.Vault.AuthMethod = AuthMethodAppRole
	}
	if cfg.Vault.JWTPath == "" {
		cfg.Vault.JWTPath = DefaultJWTPath
	}
	return &cfg, nil
}

// ValidateCA rejects a config that could not reach the CA chain endpoint. It
// deliberately ignores every auth key: the endpoint is unauthenticated.
func (v VaultConfig) ValidateCA() error {
	if v.Addr == "" {
		return fmt.Errorf("vault.addr is required")
	}
	if _, err := v.RequestTimeout(); err != nil {
		return err
	}
	return nil
}

// Validate rejects a config that could not produce a certificate, naming the
// key at fault. It never falls back from one auth method to another.
func (v VaultConfig) Validate() error {
	if v.Addr == "" {
		return fmt.Errorf("vault.addr is required")
	}
	if v.MountPoint == "" {
		return fmt.Errorf("vault.mount_point is required")
	}
	if v.RoleName == "" {
		return fmt.Errorf("vault.role_name is required")
	}
	if _, err := v.RequestTimeout(); err != nil {
		return err
	}

	switch v.AuthMethod {
	case AuthMethodAppRole:
		if v.RoleID == "" {
			return fmt.Errorf("vault.role_id is required for auth_method %q", v.AuthMethod)
		}
		if v.ApprolePath == "" {
			return fmt.Errorf("vault.approle_path is required for auth_method %q", v.AuthMethod)
		}
	case AuthMethodKubernetes:
		if v.K8sMount == "" {
			return fmt.Errorf("vault.k8s_mount is required for auth_method %q", v.AuthMethod)
		}
		if v.K8sRole == "" {
			return fmt.Errorf("vault.k8s_role is required for auth_method %q", v.AuthMethod)
		}
	default:
		return fmt.Errorf("unknown vault.auth_method %q (valid: %s, %s)",
			v.AuthMethod, AuthMethodAppRole, AuthMethodKubernetes)
	}
	return nil
}
