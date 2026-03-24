package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AuthMethod selects how certmanager authenticates to Vault.
type AuthMethod string

const (
	AuthMethodAppRole    AuthMethod = "approle"
	AuthMethodLDAP       AuthMethod = "ldap"
	AuthMethodKubernetes AuthMethod = "kubernetes"
	AuthMethodToken      AuthMethod = "token"
)

// Config is the top-level configuration structure.
type Config struct {
	Vault VaultConfig `yaml:"vault"`
}

// VaultConfig holds Vault connection and auth parameters.
// Only the fields relevant to the chosen AuthMethod need to be populated.
type VaultConfig struct {
	Addr       string     `yaml:"addr"`
	AuthMethod AuthMethod `yaml:"auth_method"` // approle | ldap | kubernetes | token
	MountPoint string     `yaml:"mount_point"`
	RoleName   string     `yaml:"role_name"`
	OutputPath string     `yaml:"output_path"`

	// approle
	ApprolePath string `yaml:"approle_path"`
	RoleID      string `yaml:"role_id"`
	SecretID    string `yaml:"secret_id"`

	// ldap
	LDAPPath     string `yaml:"ldap_path"`
	LDAPUsername string `yaml:"ldap_username"`
	LDAPPassword string `yaml:"ldap_password"`

	// kubernetes
	KubernetesPath      string `yaml:"kubernetes_path"`
	KubernetesRole      string `yaml:"kubernetes_role"`
	KubernetesTokenFile string `yaml:"kubernetes_token_file"`

	// token (static; useful for testing or bootstrap)
	Token string `yaml:"token"`
}

// DefaultPath returns the XDG-compliant default config file path:
// $XDG_CONFIG_HOME/certmanager/config.yaml, falling back to
// $HOME/.config/certmanager/config.yaml.
func DefaultPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "config.yaml"
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "certmanager", "config.yaml")
}

// Load reads and parses the config file at the given path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	// Default to approle for backwards-compatibility with the existing
	// Python certmanager/sshsignhost config format.
	if cfg.Vault.AuthMethod == "" {
		cfg.Vault.AuthMethod = AuthMethodAppRole
	}

	return &cfg, nil
}
