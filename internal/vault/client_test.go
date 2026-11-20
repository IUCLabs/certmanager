package vault_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/vault"
)

func newServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func baseConfig(addr string) config.VaultConfig {
	return config.VaultConfig{
		Addr:        addr,
		AuthMethod:  config.AuthMethodAppRole,
		ApprolePath: "approle",
		RoleID:      "role-id",
		MountPoint:  "pki_int",
		RoleName:    "my-role",
	}
}

func TestNewAppRoleSendsRoleIDOnly(t *testing.T) {
	var body map[string]any
	var path string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
	})

	if _, err := vault.New(baseConfig(srv.URL)); err != nil {
		t.Fatalf("New: %v", err)
	}
	if path != "/v1/auth/approle/login" {
		t.Errorf("login path = %q", path)
	}
	if len(body) != 1 || body["role_id"] != "role-id" {
		t.Errorf("login body = %v, want only role_id", body)
	}
}

func TestNewKubernetesSendsRoleAndJWT(t *testing.T) {
	jwt := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwt, []byte("the-jwt\n"), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}

	var body map[string]any
	var path string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
	})

	cfg := baseConfig(srv.URL)
	cfg.AuthMethod = config.AuthMethodKubernetes
	cfg.K8sMount = "kubernetes"
	cfg.K8sRole = "my-certmanager-role"
	cfg.JWTPath = jwt

	if _, err := vault.New(cfg); err != nil {
		t.Fatalf("New: %v", err)
	}
	if path != "/v1/auth/kubernetes/login" {
		t.Errorf("login path = %q", path)
	}
	if body["role"] != "my-certmanager-role" || body["jwt"] != "the-jwt" {
		t.Errorf("login body = %v", body)
	}
}

func TestNewAuthErrors(t *testing.T) {
	deny := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
	}
	noToken := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"auth":{}}`)
	}

	tests := []struct {
		name    string
		handler http.HandlerFunc
		mutate  func(*testing.T, *config.VaultConfig)
		wantErr string
	}{
		{
			name:    "approle rejected",
			handler: deny,
			wantErr: "approle login: POST auth/approle/login: vault returned 403",
		},
		{
			name:    "approle returns no token",
			handler: noToken,
			wantErr: "no auth.client_token",
		},
		{
			name:    "kubernetes rejected",
			handler: deny,
			mutate: func(t *testing.T, c *config.VaultConfig) {
				jwt := filepath.Join(t.TempDir(), "token")
				if err := os.WriteFile(jwt, []byte("jwt"), 0o600); err != nil {
					t.Fatalf("write jwt: %v", err)
				}
				c.AuthMethod = config.AuthMethodKubernetes
				c.K8sMount = "kubernetes"
				c.K8sRole = "role"
				c.JWTPath = jwt
			},
			wantErr: "kubernetes login: POST auth/kubernetes/login: vault returned 403",
		},
		{
			name:    "kubernetes jwt missing",
			handler: noToken,
			mutate: func(t *testing.T, c *config.VaultConfig) {
				c.AuthMethod = config.AuthMethodKubernetes
				c.K8sMount = "kubernetes"
				c.K8sRole = "role"
				c.JWTPath = filepath.Join(t.TempDir(), "absent")
			},
			wantErr: "read service account token",
		},
		{
			name:    "unknown auth method",
			handler: noToken,
			mutate:  func(t *testing.T, c *config.VaultConfig) { c.AuthMethod = "ldap" },
			wantErr: `unknown vault.auth_method "ldap"`,
		},
		{
			name:    "bad timeout",
			handler: noToken,
			mutate:  func(t *testing.T, c *config.VaultConfig) { c.Timeout = "eventually" },
			wantErr: "not a valid duration",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, tc.handler)
			cfg := baseConfig(srv.URL)
			if tc.mutate != nil {
				tc.mutate(t, &cfg)
			}
			_, err := vault.New(cfg)
			if err == nil {
				t.Fatal("New succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewKubernetesEmptyJWT(t *testing.T) {
	jwt := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwt, []byte("\n\t "), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("vault must not be contacted when the JWT is empty")
		_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
	})

	cfg := baseConfig(srv.URL)
	cfg.AuthMethod = config.AuthMethodKubernetes
	cfg.K8sMount = "kubernetes"
	cfg.K8sRole = "role"
	cfg.JWTPath = jwt

	_, err := vault.New(cfg)
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("error = %v, want an empty-JWT failure", err)
	}
}

func TestPostSendsToken(t *testing.T) {
	var token string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
			return
		}
		token = r.Header.Get("X-Vault-Token")
		_, _ = fmt.Fprint(w, `{"data":{"ok":true}}`)
	})

	c, err := vault.New(baseConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var out struct {
		Data struct {
			OK bool `json:"ok"`
		} `json:"data"`
	}
	if err := c.Post("pki_int/issue/my-role", map[string]string{}, &out); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if token != "s.token" {
		t.Errorf("X-Vault-Token = %q", token)
	}
	if !out.Data.OK {
		t.Error("response not decoded")
	}
}

func TestPostTimesOut(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
			_, _ = fmt.Fprint(w, `{"data":{}}`)
		}
	})

	cfg := baseConfig(srv.URL)
	cfg.Timeout = "500ms"
	c, err := vault.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	start := time.Now()
	err = c.Post("pki_int/issue/my-role", map[string]string{}, &struct{}{})
	if err == nil {
		t.Fatal("Post succeeded, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Post took %v, the timeout did not apply", elapsed)
	}
}

func TestTLSVerificationCanBeEnabled(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
	})

	cfg := baseConfig(srv.URL)
	skip := false
	cfg.TLSSkipVerify = &skip
	if _, err := vault.New(cfg); err == nil {
		t.Fatal("New succeeded against a self-signed server with verification enabled")
	}
}

func TestNewUnauthenticatedDoesNotLogIn(t *testing.T) {
	var paths []string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if _, ok := r.Header["X-Vault-Token"]; ok {
			t.Errorf("X-Vault-Token sent to %s", r.URL.Path)
		}
		_, _ = fmt.Fprint(w, "PEM")
	})

	// No auth_method, no role_id, no JWT path: the CA chain endpoint is public.
	c, err := vault.NewUnauthenticated(config.VaultConfig{Addr: srv.URL})
	if err != nil {
		t.Fatalf("NewUnauthenticated: %v", err)
	}
	body, err := c.Get("pki_int/ca_chain")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "PEM" {
		t.Errorf("body = %q", body)
	}
	if len(paths) != 1 || paths[0] != "/v1/pki_int/ca_chain" {
		t.Errorf("requests = %v, want a single GET of the chain", paths)
	}
}

func TestGetSendsTheTokenWhenAuthenticated(t *testing.T) {
	var token string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
			return
		}
		token = r.Header.Get("X-Vault-Token")
		_, _ = fmt.Fprint(w, "PEM")
	})

	c, err := vault.New(baseConfig(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get("pki_int/ca_chain"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if token != "s.token" {
		t.Errorf("X-Vault-Token = %q", token)
	}
}

func TestGetSurfacesTheStatusAndBody(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"errors":["unsupported path"]}`)
	})

	c, err := vault.NewUnauthenticated(config.VaultConfig{Addr: srv.URL})
	if err != nil {
		t.Fatalf("NewUnauthenticated: %v", err)
	}
	if _, err := c.Get("pki_int/ca_chain"); err == nil ||
		!strings.Contains(err.Error(), "vault returned 404") ||
		!strings.Contains(err.Error(), "unsupported path") {
		t.Errorf("error = %v, want the status and Vault's message", err)
	}
}
