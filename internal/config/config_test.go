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

func TestFallbackPath(t *testing.T) {
	if got := FallbackPath(); got != "/opt/certmanager/config.yaml" {
		t.Errorf("FallbackPath() = %q, want the Puppet-managed path", got)
	}
}

// seedConfig drops a config file at dir/certmanager/config.yaml and returns it.
func seedConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "certmanager", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(approleBody), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestDefaultPathPrefersXDG(t *testing.T) {
	xdg := t.TempDir()
	home := t.TempDir()
	want := seedConfig(t, xdg)
	seedConfig(t, filepath.Join(home, ".config"))

	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", home)

	if got := DefaultPath(); got != want {
		t.Errorf("DefaultPath() = %q, want the XDG config %q", got, want)
	}
}

func TestDefaultPathFallsBackToHome(t *testing.T) {
	home := t.TempDir()
	want := seedConfig(t, filepath.Join(home, ".config"))

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)

	if got := DefaultPath(); got != want {
		t.Errorf("DefaultPath() = %q, want the home config %q", got, want)
	}
}

// XDG pointing somewhere without a config must not shadow a usable home one.
func TestDefaultPathSkipsXDGWithoutAConfig(t *testing.T) {
	home := t.TempDir()
	want := seedConfig(t, filepath.Join(home, ".config"))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", home)

	if got := DefaultPath(); got != want {
		t.Errorf("DefaultPath() = %q, want the home config %q", got, want)
	}
}

// What generate() sees: the puppet user has no usable home, so neither lookup
// yields a file and the baked-in path has to win.
func TestDefaultPathFallsBackToBakedPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	if got := DefaultPath(); got != FallbackPath() {
		t.Errorf("DefaultPath() = %q, want %q", got, FallbackPath())
	}
}

func TestDefaultPathIgnoresADirectory(t *testing.T) {
	xdg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(xdg, "certmanager", "config.yaml"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())

	if got := DefaultPath(); got != FallbackPath() {
		t.Errorf("DefaultPath() = %q, want %q", got, FallbackPath())
	}
}

func TestResolvePrefersExplicitPath(t *testing.T) {
	xdg := t.TempDir()
	resolved := seedConfig(t, xdg)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())

	explicit := writeConfig(t, approleBody)
	if got := Resolve(explicit); got != explicit {
		t.Errorf("Resolve(%q) = %q, want the explicit path", explicit, got)
	}
	if got := Resolve(""); got != resolved {
		t.Errorf("Resolve(\"\") = %q, want the resolved path %q", got, resolved)
	}
}

// The XDG spec says a non-absolute XDG_CONFIG_HOME must be ignored, so a
// config sitting under the working directory cannot be picked up.
func TestDefaultPathIgnoresRelativeXDG(t *testing.T) {
	wd := t.TempDir()
	seedConfig(t, filepath.Join(wd, "xdg"))
	t.Chdir(wd)
	t.Setenv("XDG_CONFIG_HOME", "xdg")
	t.Setenv("HOME", t.TempDir())

	if got := DefaultPath(); got != FallbackPath() {
		t.Errorf("DefaultPath() = %q, want %q", got, FallbackPath())
	}
}

// The CA chain endpoint is unauthenticated, so a config with nothing but addr
// and mount_point has to load.
func TestLoadCAWithoutCredentials(t *testing.T) {
	cfg, err := LoadCA(writeConfig(t, "vault:\n  addr: https://vault.example.com:8200\n  mount_point: pki_int\n"))
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if cfg.Vault.Addr != "https://vault.example.com:8200" {
		t.Errorf("addr = %q", cfg.Vault.Addr)
	}
	if cfg.Vault.MountPoint != "pki_int" {
		t.Errorf("mount_point = %q", cfg.Vault.MountPoint)
	}
	if cfg.Vault.RoleID != "" || cfg.Vault.RoleName != "" {
		t.Errorf("LoadCA invented credentials: %+v", cfg.Vault)
	}
}

// Load, by contrast, still demands everything issuance needs.
func TestLoadRejectsWhatLoadCAAccepts(t *testing.T) {
	path := writeConfig(t, "vault:\n  addr: https://vault.example.com:8200\n  mount_point: pki_int\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a config with no role_name or credentials")
	}
}

func TestLoadCAErrors(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"no addr", "vault:\n  mount_point: pki_int\n", "vault.addr is required"},
		{"bad timeout", "vault:\n  addr: https://v:8200\n  timeout: soon\n", "not a valid duration"},
		{"negative timeout", "vault:\n  addr: https://v:8200\n  timeout: -5s\n", "must be positive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCA(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadCAMissingFile(t *testing.T) {
	_, err := LoadCA(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "open config") {
		t.Errorf("error = %v, want an open failure", err)
	}
}

// An unknown auth_method is fatal for issuance but irrelevant to the CA path.
func TestLoadCAIgnoresAuthMethod(t *testing.T) {
	if _, err := LoadCA(writeConfig(t, "vault:\n  addr: https://v:8200\n  auth_method: ldap\n  mount_point: pki_int\n")); err != nil {
		t.Errorf("LoadCA: %v", err)
	}
}
