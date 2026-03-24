package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/vault"
)

// tokenHandler returns a handler that serves a fixed Vault token on POST.
func tokenHandler(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": token},
		})
	}
}

func newTLSServer(t *testing.T, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// AppRole
// ---------------------------------------------------------------------------

func TestNew_AppRole(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", tokenHandler("tok-approle"))
	srv := newTLSServer(t, mux)

	_, err := vault.New(config.VaultConfig{
		Addr:        srv.URL,
		AuthMethod:  config.AuthMethodAppRole,
		ApprolePath: "approle",
		RoleID:      "role-id",
	})
	if err != nil {
		t.Fatalf("AppRole auth failed: %v", err)
	}
}

func TestNew_AppRole_WithSecretID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["secret_id"] != "my-secret" {
			http.Error(w, "missing secret_id", http.StatusBadRequest)
			return
		}
		tokenHandler("tok-approle-secret")(w, r)
	})
	srv := newTLSServer(t, mux)

	_, err := vault.New(config.VaultConfig{
		Addr:        srv.URL,
		AuthMethod:  config.AuthMethodAppRole,
		ApprolePath: "approle",
		RoleID:      "role-id",
		SecretID:    "my-secret",
	})
	if err != nil {
		t.Fatalf("AppRole+SecretID auth failed: %v", err)
	}
}

func TestNew_AppRole_DefaultPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", tokenHandler("tok"))
	srv := newTLSServer(t, mux)

	_, err := vault.New(config.VaultConfig{
		Addr:       srv.URL,
		AuthMethod: config.AuthMethodAppRole,
		RoleID:     "role-id",
		// ApprolePath intentionally omitted — should default to "approle"
	})
	if err != nil {
		t.Fatalf("AppRole default path failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LDAP
// ---------------------------------------------------------------------------

func TestNew_LDAP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/ldap/login/testuser", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["password"] != "secret" {
			http.Error(w, "bad password", http.StatusForbidden)
			return
		}
		tokenHandler("tok-ldap")(w, r)
	})
	srv := newTLSServer(t, mux)

	_, err := vault.New(config.VaultConfig{
		Addr:         srv.URL,
		AuthMethod:   config.AuthMethodLDAP,
		LDAPPath:     "ldap",
		LDAPUsername: "testuser",
		LDAPPassword: "secret",
	})
	if err != nil {
		t.Fatalf("LDAP auth failed: %v", err)
	}
}

func TestNew_LDAP_DefaultPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/ldap/login/u", tokenHandler("tok"))
	srv := newTLSServer(t, mux)

	_, err := vault.New(config.VaultConfig{
		Addr:         srv.URL,
		AuthMethod:   config.AuthMethodLDAP,
		LDAPUsername: "u",
		LDAPPassword: "p",
	})
	if err != nil {
		t.Fatalf("LDAP default path failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

func TestNew_Kubernetes(t *testing.T) {
	tmp := t.TempDir()
	tokenFile := filepath.Join(tmp, "token")
	os.WriteFile(tokenFile, []byte("k8s-jwt"), 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["jwt"] != "k8s-jwt" || body["role"] != "puppet" {
			http.Error(w, "bad jwt/role", http.StatusForbidden)
			return
		}
		tokenHandler("tok-k8s")(w, r)
	})
	srv := newTLSServer(t, mux)

	_, err := vault.New(config.VaultConfig{
		Addr:                srv.URL,
		AuthMethod:          config.AuthMethodKubernetes,
		KubernetesPath:      "kubernetes",
		KubernetesRole:      "puppet",
		KubernetesTokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("Kubernetes auth failed: %v", err)
	}
}

func TestNew_Kubernetes_MissingTokenFile(t *testing.T) {
	_, err := vault.New(config.VaultConfig{
		Addr:                "https://vault.example.com",
		AuthMethod:          config.AuthMethodKubernetes,
		KubernetesRole:      "puppet",
		KubernetesTokenFile: "/nonexistent/token",
	})
	if err == nil || !strings.Contains(err.Error(), "read service account token") {
		t.Errorf("expected token file error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

func TestNew_Token(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki_int/issue/role", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "static-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": "C", "private_key": "K", "issuing_ca": "CA",
			},
		})
	})
	srv := newTLSServer(t, mux)

	client, err := vault.New(config.VaultConfig{
		Addr:       srv.URL,
		AuthMethod: config.AuthMethodToken,
		Token:      "static-token",
	})
	if err != nil {
		t.Fatalf("Token auth failed: %v", err)
	}

	var out map[string]any
	if err := client.Post("pki_int/issue/role", map[string]string{"common_name": "x"}, &out); err != nil {
		t.Fatalf("Post with token auth failed: %v", err)
	}
}

func TestNew_Token_Empty(t *testing.T) {
	_, err := vault.New(config.VaultConfig{
		Addr:       "https://vault.example.com",
		AuthMethod: config.AuthMethodToken,
		Token:      "",
	})
	if err == nil {
		t.Error("expected error for empty token")
	}
}

// ---------------------------------------------------------------------------
// Unknown auth method
// ---------------------------------------------------------------------------

func TestNew_UnknownMethod(t *testing.T) {
	_, err := vault.New(config.VaultConfig{
		Addr:       "https://vault.example.com",
		AuthMethod: "magic",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown auth_method") {
		t.Errorf("expected unknown method error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Auth failure
// ---------------------------------------------------------------------------

func TestNew_AuthFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	_, err := vault.New(config.VaultConfig{
		Addr:        srv.URL,
		AuthMethod:  config.AuthMethodAppRole,
		ApprolePath: "approle",
		RoleID:      "role-id",
	})
	if err == nil {
		t.Error("expected auth error, got nil")
	}
}

func TestNew_EmptyToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": ""},
		})
	}))
	t.Cleanup(srv.Close)

	_, err := vault.New(config.VaultConfig{
		Addr:        srv.URL,
		AuthMethod:  config.AuthMethodAppRole,
		ApprolePath: "approle",
		RoleID:      "role-id",
	})
	if err == nil || !strings.Contains(err.Error(), "empty client token") {
		t.Errorf("expected empty token error, got %v", err)
	}
}
