package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPath_XDGSet(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	got := DefaultPath()
	want := "/tmp/xdg/certmanager/config.yaml"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDefaultPath_XDGUnset(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	home, _ := os.UserHomeDir()
	got := DefaultPath()
	want := filepath.Join(home, ".config", "certmanager", "config.yaml")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLoad_AppRole(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	content := `
vault:
  addr: https://vault.example.com:8200
  auth_method: approle
  approle_path: approle
  role_id: my-role-id
  mount_point: pki_int
  role_name: my-role
  output_path: /tmp/certs
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.AuthMethod != AuthMethodAppRole {
		t.Errorf("auth_method = %q", cfg.Vault.AuthMethod)
	}
	if cfg.Vault.RoleID != "my-role-id" {
		t.Errorf("role_id = %q", cfg.Vault.RoleID)
	}
}

func TestLoad_DefaultAuthMethod(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	// Omit auth_method — should default to approle for backwards compat.
	content := `
vault:
  addr: https://vault.example.com:8200
  role_id: my-role-id
  approle_path: approle
  mount_point: pki_int
  role_name: my-role
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.AuthMethod != AuthMethodAppRole {
		t.Errorf("expected default approle, got %q", cfg.Vault.AuthMethod)
	}
}

func TestLoad_LDAP(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	content := `
vault:
  addr: https://vault.example.com:8200
  auth_method: ldap
  ldap_path: ldap
  ldap_username: alice
  ldap_password: secret
  mount_point: pki_int
  role_name: my-role
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.AuthMethod != AuthMethodLDAP {
		t.Errorf("auth_method = %q", cfg.Vault.AuthMethod)
	}
	if cfg.Vault.LDAPUsername != "alice" {
		t.Errorf("ldap_username = %q", cfg.Vault.LDAPUsername)
	}
}

func TestLoad_Kubernetes(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	content := `
vault:
  addr: https://vault.example.com:8200
  auth_method: kubernetes
  kubernetes_path: kubernetes
  kubernetes_role: puppet
  kubernetes_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
  mount_point: pki_int
  role_name: my-role
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.AuthMethod != AuthMethodKubernetes {
		t.Errorf("auth_method = %q", cfg.Vault.AuthMethod)
	}
	if cfg.Vault.KubernetesRole != "puppet" {
		t.Errorf("kubernetes_role = %q", cfg.Vault.KubernetesRole)
	}
}

func TestLoad_Token(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	content := `
vault:
  addr: https://vault.example.com:8200
  auth_method: token
  token: hvs.statictoken
  mount_point: pki_int
  role_name: my-role
`
	os.WriteFile(path, []byte(content), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Vault.AuthMethod != AuthMethodToken {
		t.Errorf("auth_method = %q", cfg.Vault.AuthMethod)
	}
	if cfg.Vault.Token != "hvs.statictoken" {
		t.Errorf("token = %q", cfg.Vault.Token)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}
