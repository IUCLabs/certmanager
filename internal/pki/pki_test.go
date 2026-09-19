package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

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
		Certificate: "CERT",
		PrivateKey:  "KEY",
		FullChain:   "CERT\nCA",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IssueCert = %+v, want %+v", got, want)
	}
	// Leaf first: asserted as an order, not as membership.
	if got.FullChain != got.Certificate+"\n"+"CA" {
		t.Errorf("full_chain = %q, want the leaf ahead of the issuing CA", got.FullChain)
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
		Certificate: "CERT",
		PrivateKey:  "KEY",
		FullChain:   "CERT\nCA",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"certificate":"CERT","private_key":"KEY","full_chain":"CERT\nCA"}`
	if string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}

// newCAServer serves the CA chain endpoint and records what the client sent.
func newCAServer(t *testing.T, h http.HandlerFunc) (*vault.Client, *caCapture) {
	t.Helper()
	got := &caCapture{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		_, got.tokenSet = r.Header["X-Vault-Token"]
		if strings.HasSuffix(r.URL.Path, "/login") {
			got.loggedIn = true
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)

	c, err := vault.NewUnauthenticated(config.VaultConfig{Addr: srv.URL})
	if err != nil {
		t.Fatalf("vault.NewUnauthenticated: %v", err)
	}
	return c, got
}

type caCapture struct {
	method   string
	path     string
	tokenSet bool
	loggedIn bool
}

func testChainPEM(t *testing.T) string {
	t.Helper()
	return testCertPEM(t, "intermediate") + testCertPEM(t, "root")
}

func testCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestFetchCAChain(t *testing.T) {
	chain := testChainPEM(t)
	c, got := newCAServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// Vault labels the PEM body application/pkix-cert.
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = io.WriteString(w, chain)
	})

	out, err := pki.FetchCAChain(c, "pki_int")
	if err != nil {
		t.Fatalf("FetchCAChain: %v", err)
	}

	if got.method != http.MethodGet {
		t.Errorf("method = %q, want GET", got.method)
	}
	if got.path != "/v1/pki_int/ca_chain" {
		t.Errorf("path = %q", got.path)
	}
	if got.tokenSet {
		t.Error("X-Vault-Token must not be sent to the CA chain endpoint")
	}
	if got.loggedIn {
		t.Error("the CA chain path must not authenticate")
	}
	if out != strings.TrimSpace(chain)+"\n" {
		t.Errorf("chain = %q, want %q", out, chain)
	}
	if n := strings.Count(out, "-----BEGIN CERTIFICATE-----"); n != 2 {
		t.Errorf("chain carries %d certificates, want 2", n)
	}
}

func TestFetchCAChainFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "non-200",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"errors":["permission denied"]}`)
			},
			wantErr: "vault returned 403",
		},
		{
			name:    "empty body",
			handler: func(http.ResponseWriter, *http.Request) {},
			wantErr: "empty CA chain",
		},
		{
			name: "not PEM",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "definitely not a certificate")
			},
			wantErr: "not a PEM certificate chain",
		},
		{
			name: "wrong PEM type",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
			},
			wantErr: "not a CERTIFICATE",
		},
		{
			name: "corrupt certificate",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
			},
			wantErr: "parse certificate 1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newCAServer(t, tc.handler)
			out, err := pki.FetchCAChain(c, "pki_int")
			if err == nil {
				t.Fatalf("FetchCAChain succeeded, want an error (got %q)", out)
			}
			if out != "" {
				t.Errorf("a failing FetchCAChain must return no chain, got %q", out)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
