package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const approleBody = `vault:
  addr: https://vault.example.com:8200
  approle_path: approle
  role_id: abc-123
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certmanager
`

func TestLoadAppRoleDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, approleBody))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Vault.AuthMethod != AuthMethodAppRole {
		t.Errorf("auth_method = %q, want %q (default)", cfg.Vault.AuthMethod, AuthMethodAppRole)
	}
	if cfg.Vault.JWTPath != DefaultJWTPath {
		t.Errorf("jwt_path = %q, want %q", cfg.Vault.JWTPath, DefaultJWTPath)
	}
	if cfg.Vault.OutputPath != "/tmp/certmanager" {
		t.Errorf("output_path = %q, want it read from under vault:", cfg.Vault.OutputPath)
	}
	if !cfg.Vault.SkipTLSVerify() {
		t.Error("tls_skip_verify must default to true")
	}
	d, err := cfg.Vault.RequestTimeout()
	if err != nil || d != DefaultTimeout {
		t.Errorf("RequestTimeout() = %v, %v, want %v", d, err, DefaultTimeout)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(writeConfig(t, approleBody+"  tls_skip_verify: false\n  timeout: 5s\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Vault.SkipTLSVerify() {
		t.Error("tls_skip_verify: false must disable skipping")
	}
	d, err := cfg.Vault.RequestTimeout()
	if err != nil || d != 5*time.Second {
		t.Errorf("RequestTimeout() = %v, %v, want 5s", d, err)
	}
}

func TestLoadKubernetes(t *testing.T) {
	cfg, err := Load(writeConfig(t, `vault:
  addr: https://vault.example.com:8200
  auth_method: kubernetes
  k8s_mount: kubernetes
  k8s_role: my-certmanager-role
  mount_point: pki_int
  role_name: my-role
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Vault.K8sMount != "kubernetes" || cfg.Vault.K8sRole != "my-certmanager-role" {
		t.Errorf("kubernetes keys not parsed: %+v", cfg.Vault)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"missing addr", "vault:\n  mount_point: pki_int\n  role_name: r\n  role_id: x\n  approle_path: approle\n", "vault.addr"},
		{"missing mount_point", "vault:\n  addr: https://v:8200\n  role_name: r\n  role_id: x\n  approle_path: approle\n", "vault.mount_point"},
		{"missing role_name", "vault:\n  addr: https://v:8200\n  mount_point: pki_int\n  role_id: x\n  approle_path: approle\n", "vault.role_name"},
		{"missing role_id", "vault:\n  addr: https://v:8200\n  mount_point: pki_int\n  role_name: r\n  approle_path: approle\n", "vault.role_id"},
		{"missing approle_path", "vault:\n  addr: https://v:8200\n  mount_point: pki_int\n  role_name: r\n  role_id: x\n", "vault.approle_path"},
		{"missing k8s_mount", "vault:\n  addr: https://v:8200\n  auth_method: kubernetes\n  k8s_role: r\n  mount_point: pki_int\n  role_name: r\n", "vault.k8s_mount"},
		{"missing k8s_role", "vault:\n  addr: https://v:8200\n  auth_method: kubernetes\n  k8s_mount: m\n  mount_point: pki_int\n  role_name: r\n", "vault.k8s_role"},
		{"unknown auth method", "vault:\n  addr: https://v:8200\n  auth_method: token\n  mount_point: pki_int\n  role_name: r\n", `unknown vault.auth_method "token"`},
		{"bad timeout", approleBody + "  timeout: soon\n", "not a valid duration"},
		{"zero timeout", approleBody + "  timeout: 0s\n", "must be positive"},
		{"malformed yaml", "vault: [\n", "parse config"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Fatalf("error = %v, want an open config failure", err)
	}
}

func TestDefaultPath(t *testing.T) {
	if got := DefaultPath(); got != "/opt/certmanager/config.yaml" {
		t.Errorf("DefaultPath() = %q, want the Puppet-managed path", got)
	}
}
