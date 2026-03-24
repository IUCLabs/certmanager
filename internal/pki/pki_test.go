package pki_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/pki"
	"github.com/IUCLabs/certmanager/internal/vault"
)

func newVaultClient(t *testing.T, mux *http.ServeMux) *vault.Client {
	t.Helper()
	const token = "test-token"
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": token},
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	client, err := vault.New(config.VaultConfig{
		Addr:        srv.URL,
		AuthMethod:  config.AuthMethodAppRole,
		RoleID:      "role",
		ApprolePath: "approle",
	})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return client
}

func TestIssueCert(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki_int/issue/my-role", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": "CERT",
				"private_key": "KEY",
				"issuing_ca":  "CA",
			},
		})
	})

	client := newVaultClient(t, mux)
	cert, err := pki.IssueCert(client, "pki_int", "my-role", "host.example.com",
		[]string{"host", "host.example.com"}, []string{"127.0.0.1"}, 90)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	if cert.Certificate != "CERT" {
		t.Errorf("certificate = %q", cert.Certificate)
	}
	if cert.PrivateKey != "KEY" {
		t.Errorf("private_key = %q", cert.PrivateKey)
	}
	if cert.CACertificate != "CA" {
		t.Errorf("ca_certificate = %q", cert.CACertificate)
	}
	if !strings.Contains(cert.FullChain, "CA") || !strings.Contains(cert.FullChain, "CERT") {
		t.Errorf("full_chain = %q", cert.FullChain)
	}
}

func TestIssueCert_VaultError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki_int/issue/my-role", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	})

	client := newVaultClient(t, mux)
	_, err := pki.IssueCert(client, "pki_int", "my-role", "host.example.com", nil, nil, 90)
	if err == nil {
		t.Error("expected error, got nil")
	}
}
