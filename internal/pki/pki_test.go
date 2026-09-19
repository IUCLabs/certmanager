package pki_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/pki"
	"github.com/IUCLabs/certmanager/internal/vault"
)

func newClient(t *testing.T, issue http.HandlerFunc) *vault.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.token"}}`)
			return
		}
		issue(w, r)
	}))
	t.Cleanup(srv.Close)

	c, err := vault.New(config.VaultConfig{
		Addr:        srv.URL,
		AuthMethod:  config.AuthMethodAppRole,
		ApprolePath: "approle",
		RoleID:      "role-id",
		MountPoint:  "pki_int",
		RoleName:    "my-role",
	})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return c
}

func TestIssueCert(t *testing.T) {
	var path string
	var body map[string]any
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = fmt.Fprint(w, `{"data":{"certificate":"CERT","private_key":"KEY","issuing_ca":"CA"}}`)
	})

	got, err := pki.IssueCert(c, "pki_int", "my-role", "host.example.com",
		[]string{"host", "host.example.com"}, []string{"127.0.0.1", "192.0.2.5"}, 90)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	if path != "/v1/pki_int/issue/my-role" {
		t.Errorf("issue path = %q", path)
	}
	wantBody := map[string]any{
		"common_name": "host.example.com",
		"alt_names":   "host,host.example.com",
		"ip_sans":     "127.0.0.1,192.0.2.5",
		"ttl":         "90d",
	}
	if !reflect.DeepEqual(body, wantBody) {
		t.Errorf("issue body = %v, want %v", body, wantBody)
	}

	want := &pki.CertificateResponse{
		Certificate:   "CERT",
		PrivateKey:    "KEY",
		FullChain:     "CA\nCERT",
		CACertificate: "CA",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IssueCert = %+v, want %+v", got, want)
	}
}

func TestIssueCertSendsEmptySANFields(t *testing.T) {
	var body map[string]any
	c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = fmt.Fprint(w, `{"data":{"certificate":"CERT","private_key":"KEY","issuing_ca":"CA"}}`)
	})

	if _, err := pki.IssueCert(c, "pki_int", "my-role", "host", nil, nil, 365); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if body["alt_names"] != "" || body["ip_sans"] != "" {
		t.Errorf("empty SANs must be sent as empty strings, got %v", body)
	}
	if body["ttl"] != "365d" {
		t.Errorf("ttl = %v, want 365d", body["ttl"])
	}
}

func TestIssueCertVaultError(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"errors":["common name not allowed"]}`)
	})

	_, err := pki.IssueCert(c, "pki_int", "my-role", "host", nil, nil, 90)
	if err == nil {
		t.Fatal("IssueCert succeeded, want error")
	}
	if !strings.Contains(err.Error(), "vault returned 400") || !strings.Contains(err.Error(), "common name not allowed") {
		t.Errorf("error = %v, want the status and Vault's message", err)
	}
}

func TestIssueCertEmptyPayload(t *testing.T) {
	c := newClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"data":{}}`)
	})

	_, err := pki.IssueCert(c, "pki_int", "my-role", "host", nil, nil, 90)
	if err == nil || !strings.Contains(err.Error(), "no certificate data") {
		t.Fatalf("error = %v, want a missing-data failure", err)
	}
}

func TestCertificateResponseJSONKeyOrder(t *testing.T) {
	b, err := json.Marshal(&pki.CertificateResponse{
		Certificate:   "CERT",
		PrivateKey:    "KEY",
		FullChain:     "CA\nCERT",
		CACertificate: "CA",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"certificate":"CERT","private_key":"KEY","full_chain":"CA\nCERT","ca_certificate":"CA"}`
	if string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}
