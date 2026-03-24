package ssh_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/ssh"
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

func TestSignHostCert(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ssh-host-signer/sign/hostrole", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"signed_key": "ssh-rsa-cert-v01@openssh.com AAAA...",
			},
		})
	})

	client := newVaultClient(t, mux)
	resp, err := ssh.SignHostCert(client, "ssh-host-signer", "hostrole",
		"ssh-rsa AAAA...", []string{"host.example.com", "host"}, "87600h")
	if err != nil {
		t.Fatalf("SignHostCert: %v", err)
	}

	if resp.SignedKey != "ssh-rsa-cert-v01@openssh.com AAAA..." {
		t.Errorf("signed_key = %q", resp.SignedKey)
	}
}

func TestSignHostCert_DefaultTTL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ssh-host-signer/sign/hostrole", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["ttl"] != "87600h" {
			t.Errorf("expected default ttl 87600h, got %q", body["ttl"])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"signed_key": "CERT"},
		})
	})

	client := newVaultClient(t, mux)
	_, err := ssh.SignHostCert(client, "ssh-host-signer", "hostrole", "ssh-rsa AAAA...", []string{"host"}, "")
	if err != nil {
		t.Fatalf("SignHostCert: %v", err)
	}
}

func TestSignHostCert_EmptySignedKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ssh-host-signer/sign/hostrole", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"signed_key": ""},
		})
	})

	client := newVaultClient(t, mux)
	_, err := ssh.SignHostCert(client, "ssh-host-signer", "hostrole", "ssh-rsa AAAA...", []string{"host"}, "87600h")
	if err == nil {
		t.Error("expected error for empty signed_key, got nil")
	}
}
