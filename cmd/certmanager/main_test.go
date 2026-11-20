package main

import (
	"archive/zip"
	"bytes"
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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/IUCLabs/certmanager/internal/config"
)

const (
	testCert = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
	testKey  = "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----"
	testCA   = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"
)

type stubOptions struct {
	approleStatus int
	k8sStatus     int
	issueStatus   int
	// issueHang blocks the issue call until the client gives up.
	issueHang bool

	caStatus int
	// caBody overrides the CA chain response; caBodySet distinguishes an
	// intentional empty body from "unset".
	caBody    string
	caBodySet bool
}

type capture struct {
	authPath  string
	authBody  map[string]any
	issueBody map[string]any
	token     string

	caPath      string
	caRequested bool
	// caToken records the header verbatim; the CA endpoint must be called
	// without one.
	caToken    string
	caTokenSet bool
	// chain is the PEM the stub serves from /ca_chain.
	chain string
}

// caChainPEM is a real two certificate PEM chain, since the ca path parses what
// Vault returns rather than trusting the content type.
func caChainPEM(t *testing.T) string {
	t.Helper()
	return selfSignedPEM(t, "test intermediate") + selfSignedPEM(t, "test root")
}

func selfSignedPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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

func newVaultStub(t *testing.T, opts stubOptions) (*httptest.Server, *capture) {
	t.Helper()
	defaultChain := caChainPEM(t)
	got := &capture{chain: defaultChain}

	decode := func(r *http.Request) map[string]any {
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			t.Errorf("decode request body for %s: %v", r.URL.Path, err)
		}
		return m
	}
	login := func(w http.ResponseWriter, r *http.Request, status int) {
		got.authPath = r.URL.Path
		got.authBody = decode(r)
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.testtoken"}}`)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r, orOK(opts.approleStatus))
	})
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r, orOK(opts.k8sStatus))
	})
	mux.HandleFunc("/v1/pki_int/issue/my-role", func(w http.ResponseWriter, r *http.Request) {
		if opts.issueHang {
			// Draining the body lets the server notice the client hanging up.
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			return
		}
		got.token = r.Header.Get("X-Vault-Token")
		got.issueBody = decode(r)
		if s := orOK(opts.issueStatus); s != http.StatusOK {
			w.WriteHeader(s)
			_, _ = fmt.Fprint(w, `{"errors":["common name not allowed by this role"]}`)
			return
		}
		resp := map[string]any{"data": map[string]string{
			"certificate": testCert,
			"private_key": testKey,
			"issuing_ca":  testCA,
		}}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/pki_int/ca_chain", func(w http.ResponseWriter, r *http.Request) {
		got.caRequested = true
		got.caPath = r.URL.Path
		got.caToken = r.Header.Get("X-Vault-Token")
		_, got.caTokenSet = r.Header["X-Vault-Token"]

		if s := orOK(opts.caStatus); s != http.StatusOK {
			w.WriteHeader(s)
			_, _ = fmt.Fprint(w, `{"errors":["unsupported path"]}`)
			return
		}
		body := opts.caBody
		if !opts.caBodySet {
			body = defaultChain
		}
		// Vault advertises pkix-cert while serving PEM; the stub does too, so
		// nothing downstream may sniff the content type.
		w.Header().Set("Content-Type", "application/pkix-cert")
		_, _ = io.WriteString(w, body)
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, got
}

func orOK(status int) int {
	if status == 0 {
		return http.StatusOK
	}
	return status
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func approleConfig(t *testing.T, addr string, extra ...string) string {
	t.Helper()
	return writeConfig(t, "vault:\n"+
		"  addr: "+addr+"\n"+
		"  auth_method: approle\n"+
		"  approle_path: approle\n"+
		"  role_id: test-role-id\n"+
		"  mount_point: pki_int\n"+
		"  role_name: my-role\n"+
		strings.Join(extra, ""))
}

// The exact argv Puppet's generate() uses in profiles::pki::vault.
func puppetArgs(cfgPath string) []string {
	return []string{
		"host.example.com",
		"--config", cfgPath,
		"--alt-names", "host,host.example.com",
		"--ip-sans", "127.0.0.1,192.0.2.5",
		"--expiry-days", "90",
		"--json",
	}
}

func TestRunJSONGolden(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	cfg := approleConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run(puppetArgs(cfg), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	want := `{"certificate":"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",` +
		`"private_key":"-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----",` +
		`"full_chain":"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"}` + "\n"
	if stdout.String() != want {
		t.Errorf("stdout mismatch\n got: %q\nwant: %q", stdout.String(), want)
	}

	// The whole point of --json: parsejson() must be able to read it.
	var parsed map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if _, ok := parsed["ca_certificate"]; ok {
		t.Error("ca_certificate must not be emitted; the CA comes from the ca subcommand")
	}
	if len(parsed) != 3 {
		t.Errorf("document has %d keys, want exactly 3: %v", len(parsed), parsed)
	}
	// Leaf first, issuer after -- asserted as an ordering, not a membership.
	if parsed["full_chain"] != testCert+"\n"+testCA {
		t.Errorf("full_chain = %q, want leaf then issuing CA", parsed["full_chain"])
	}
	if strings.Index(parsed["full_chain"], "LEAF") > strings.Index(parsed["full_chain"], "\nCA\n") {
		t.Errorf("full_chain puts the CA ahead of the leaf: %q", parsed["full_chain"])
	}

	if got.token != "s.testtoken" {
		t.Errorf("X-Vault-Token = %q", got.token)
	}
	if got.authBody["role_id"] != "test-role-id" {
		t.Errorf("approle body = %v", got.authBody)
	}
	if _, ok := got.authBody["secret_id"]; ok {
		t.Errorf("approle body must not carry secret_id: %v", got.authBody)
	}
	wantIssue := map[string]any{
		"common_name": "host.example.com",
		"alt_names":   "host,host.example.com",
		"ip_sans":     "127.0.0.1,192.0.2.5",
		"ttl":         "90d",
	}
	if !reflect.DeepEqual(got.issueBody, wantIssue) {
		t.Errorf("issue body = %v, want %v", got.issueBody, wantIssue)
	}
}

// generate() is invoked with combine: true, which dups stderr onto stdout at
// spawn. Anything on stderr lands inside the JSON and breaks parsejson().
func TestRunSuccessWritesNothingToStderr(t *testing.T) {
	srv, _ := newVaultStub(t, stubOptions{})
	cfg := approleConfig(t, srv.URL)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	var stdout bytes.Buffer
	code := run(puppetArgs(cfg), &stdout, os.Stderr)

	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if len(captured) != 0 {
		t.Errorf("stderr must be empty on the success path, got %q", captured)
	}
	if !json.Valid(stdout.Bytes()) {
		t.Errorf("stdout is not valid JSON: %q", stdout.String())
	}
}

func TestRunFailures(t *testing.T) {
	emptyJWT := filepath.Join(t.TempDir(), "empty-token")
	if err := os.WriteFile(emptyJWT, []byte("  \n"), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}
	goodJWT := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(goodJWT, []byte("jwt-value\n"), 0o600); err != nil {
		t.Fatalf("write jwt: %v", err)
	}

	k8sConfig := func(t *testing.T, addr, jwtPath string) string {
		return writeConfig(t, "vault:\n"+
			"  addr: "+addr+"\n"+
			"  auth_method: kubernetes\n"+
			"  k8s_mount: kubernetes\n"+
			"  k8s_role: my-certmanager-role\n"+
			"  jwt_path: "+jwtPath+"\n"+
			"  mount_point: pki_int\n"+
			"  role_name: my-role\n")
	}

	tests := []struct {
		name    string
		opts    stubOptions
		config  func(t *testing.T, addr string) string
		wantErr string
	}{
		{
			name: "approle login rejected",
			opts: stubOptions{approleStatus: http.StatusForbidden},
			config: func(t *testing.T, addr string) string {
				return approleConfig(t, addr)
			},
			wantErr: "approle login",
		},
		{
			name: "kubernetes login rejected",
			opts: stubOptions{k8sStatus: http.StatusForbidden},
			config: func(t *testing.T, addr string) string {
				return k8sConfig(t, addr, goodJWT)
			},
			wantErr: "kubernetes login",
		},
		{
			name: "kubernetes jwt missing",
			config: func(t *testing.T, addr string) string {
				return k8sConfig(t, addr, filepath.Join(t.TempDir(), "absent"))
			},
			wantErr: "read service account token",
		},
		{
			name: "kubernetes jwt empty",
			config: func(t *testing.T, addr string) string {
				return k8sConfig(t, addr, emptyJWT)
			},
			wantErr: "is empty",
		},
		{
			name: "unknown auth method",
			config: func(t *testing.T, addr string) string {
				return writeConfig(t, "vault:\n"+
					"  addr: "+addr+"\n"+
					"  auth_method: ldap\n"+
					"  mount_point: pki_int\n"+
					"  role_name: my-role\n")
			},
			wantErr: `unknown vault.auth_method "ldap"`,
		},
		{
			name: "issue rejected",
			opts: stubOptions{issueStatus: http.StatusBadRequest},
			config: func(t *testing.T, addr string) string {
				return approleConfig(t, addr)
			},
			wantErr: "vault returned 400",
		},
		{
			name: "vault times out",
			opts: stubOptions{issueHang: true},
			config: func(t *testing.T, addr string) string {
				return approleConfig(t, addr, "  timeout: 500ms\n")
			},
			wantErr: "POST pki_int/issue/my-role",
		},
		{
			name: "missing config file",
			config: func(t *testing.T, addr string) string {
				return filepath.Join(t.TempDir(), "nope.yaml")
			},
			wantErr: "open config",
		},
		{
			name: "tls verification enabled rejects the self-signed stub",
			config: func(t *testing.T, addr string) string {
				return approleConfig(t, addr, "  tls_skip_verify: false\n")
			},
			wantErr: "approle login",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newVaultStub(t, tc.opts)
			var stdout, stderr bytes.Buffer
			code := run(puppetArgs(tc.config(t, srv.URL)), &stdout, &stderr)

			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero (stdout %q)", stdout.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout must stay empty on failure, got %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

func TestRunRequiresCommonName(t *testing.T) {
	srv, _ := newVaultStub(t, stubOptions{})
	cfg := approleConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--config", cfg, "--json"}, &stdout, &stderr); code == 0 {
		t.Fatal("exit code = 0, want non-zero")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunWritesFiles(t *testing.T) {
	srv, _ := newVaultStub(t, stubOptions{})
	out := t.TempDir()
	cfg := approleConfig(t, srv.URL, "  output_path: "+out+"\n")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"host.example.com", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code != 0: %s", stderr.String())
	}

	want := map[string]string{
		"certificate.crt": testCert,
		"private.key":     testKey,
		"full_chain.crt":  testCert + "\n" + testCA,
	}
	if _, err := os.Stat(filepath.Join(out, "host.example.com", "ca_certificate.crt")); !os.IsNotExist(err) {
		t.Errorf("ca_certificate.crt must no longer be written by the issue path (stat err = %v)", err)
	}
	for name, body := range want {
		got, err := os.ReadFile(filepath.Join(out, "host.example.com", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != body {
			t.Errorf("%s = %q, want %q", name, got, body)
		}
	}

	info, err := os.Stat(filepath.Join(out, "host.example.com", "private.key"))
	if err != nil {
		t.Fatalf("stat private.key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private.key mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestRunCompress(t *testing.T) {
	srv, _ := newVaultStub(t, stubOptions{})
	out := t.TempDir()
	cfg := approleConfig(t, srv.URL, "  output_path: "+out+"\n")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"host.example.com", "--config", cfg, "-c"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code != 0: %s", stderr.String())
	}

	zr, err := zip.OpenReader(filepath.Join(out, "host.example.com.zip"))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer func() { _ = zr.Close() }()

	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	wantNames := []string{"certificate.crt", "private.key", "full_chain.crt"}
	if !reflect.DeepEqual(names, wantNames) {
		t.Errorf("zip entries = %v, want %v", names, wantNames)
	}
}

func TestParseList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "host", []string{"host"}},
		{"puppet alt names", "host,host.example.com", []string{"host", "host.example.com"}},
		{"puppet ip sans", "127.0.0.1,192.0.2.5", []string{"127.0.0.1", "192.0.2.5"}},
		{"trailing comma", "host,", []string{"host"}},
		{"leading comma", ",host", []string{"host"}},
		{"double comma", "a,,b", []string{"a", "b"}},
		{"only commas", ",,,", nil},
		{"whitespace trimmed", " a , b ", []string{"a", "b"}},
		{"whitespace only token", "a, ,b", []string{"a", "b"}},
		{"tabs and newlines", "a,\tb\n", []string{"a", "b"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseList(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseList(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCompletionSubcommand(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{"completion", shell}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Error("completion script is empty")
			}
		})
	}
}

// authlessConfig carries only addr and mount_point: the CA chain endpoint is
// public, so the ca subcommand must not need auth keys to be present.
func authlessConfig(t *testing.T, addr string, extra ...string) string {
	t.Helper()
	return writeConfig(t, "vault:\n"+
		"  addr: "+addr+"\n"+
		"  mount_point: pki_int\n"+
		strings.Join(extra, ""))
}

func TestRunCAPrintsChain(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	cfg := authlessConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"ca", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	if got.caPath != "/v1/pki_int/ca_chain" {
		t.Errorf("requested path = %q, want /v1/pki_int/ca_chain", got.caPath)
	}
	// Unauthenticated: the header must be absent, not merely empty.
	if got.caTokenSet {
		t.Errorf("X-Vault-Token must not be sent to the CA endpoint, got %q", got.caToken)
	}
	if got.issueBody != nil {
		t.Error("the ca subcommand must not issue a certificate")
	}

	want := strings.TrimSpace(got.chain) + "\n"
	if stdout.String() != want {
		t.Errorf("stdout = %q, want the PEM chain %q", stdout.String(), want)
	}
	if n := strings.Count(stdout.String(), "-----BEGIN CERTIFICATE-----"); n != 2 {
		t.Errorf("stdout carries %d certificates, want 2", n)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// "ca" is the subcommand, never a common name to issue for.
func TestRunCAIsNotTreatedAsACommonName(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	cfg := approleConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"ca", "--config", cfg}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !got.caRequested {
		t.Error("the CA chain endpoint was never called")
	}
	if got.issueBody != nil {
		t.Errorf("issuance was attempted for common name %v", got.issueBody["common_name"])
	}
	if got.authPath != "" {
		t.Errorf("the ca subcommand logged in at %q; it must not authenticate", got.authPath)
	}
}

// The positional issue form must keep parsing unchanged now that a subcommand
// sits alongside it.
func TestRunPositionalFormStillParses(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	cfg := approleConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run(puppetArgs(cfg), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if got.issueBody["common_name"] != "host.example.com" {
		t.Errorf("common_name = %v", got.issueBody["common_name"])
	}
	if got.caRequested {
		t.Error("the issue path must not call the CA chain endpoint")
	}
}

func TestRunCAMountFlagOverridesConfig(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	cfg := writeConfig(t, "vault:\n  addr: "+srv.URL+"\n")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"ca", "--config", cfg, "--mount", "pki_int"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if got.caPath != "/v1/pki_int/ca_chain" {
		t.Errorf("requested path = %q", got.caPath)
	}
}

func TestRunCASuccessWritesNothingToStderr(t *testing.T) {
	srv, _ := newVaultStub(t, stubOptions{})
	cfg := authlessConfig(t, srv.URL)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	var stdout bytes.Buffer
	code := run([]string{"ca", "--config", cfg}, &stdout, os.Stderr)

	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}

	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if len(captured) != 0 {
		t.Errorf("stderr must be byte-empty on the ca success path, got %q", captured)
	}
	if stdout.Len() == 0 {
		t.Error("stdout is empty")
	}
}

func TestRunCAFailures(t *testing.T) {
	tests := []struct {
		name    string
		opts    stubOptions
		config  func(t *testing.T, addr string) string
		args    func(cfg string) []string
		wantErr string
	}{
		{
			name:    "vault rejects the request",
			opts:    stubOptions{caStatus: http.StatusForbidden},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: "vault returned 403",
		},
		{
			name:    "mount does not exist",
			opts:    stubOptions{caStatus: http.StatusNotFound},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: "vault returned 404",
		},
		{
			name:    "empty body",
			opts:    stubOptions{caBody: "", caBodySet: true},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: "empty CA chain",
		},
		{
			name:    "whitespace only body",
			opts:    stubOptions{caBody: "\n  \n", caBodySet: true},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: "empty CA chain",
		},
		{
			name:    "body is not PEM",
			opts:    stubOptions{caBody: "<html>nope</html>", caBodySet: true},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: "not a PEM certificate chain",
		},
		{
			name:    "PEM block is not a certificate",
			opts:    stubOptions{caBody: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", caBodySet: true},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: `not a CERTIFICATE`,
		},
		{
			name:    "PEM certificate is corrupt",
			opts:    stubOptions{caBody: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", caBodySet: true},
			config:  func(t *testing.T, addr string) string { return authlessConfig(t, addr) },
			wantErr: "parse certificate 1",
		},
		{
			name: "missing config file",
			config: func(t *testing.T, _ string) string {
				return filepath.Join(t.TempDir(), "nope.yaml")
			},
			wantErr: "open config",
		},
		{
			name: "config without addr",
			config: func(t *testing.T, _ string) string {
				return writeConfig(t, "vault:\n  mount_point: pki_int\n")
			},
			wantErr: "vault.addr is required",
		},
		{
			name: "no mount anywhere",
			config: func(t *testing.T, addr string) string {
				return writeConfig(t, "vault:\n  addr: "+addr+"\n")
			},
			wantErr: "vault.mount_point is required",
		},
		{
			name: "vault is unreachable",
			config: func(t *testing.T, _ string) string {
				return authlessConfig(t, "https://127.0.0.1:1", "  timeout: 200ms\n")
			},
			wantErr: "GET pki_int/ca_chain",
		},
		{
			name: "ca takes no positional arguments",
			config: func(t *testing.T, addr string) string {
				return authlessConfig(t, addr)
			},
			args:    func(cfg string) []string { return []string{"ca", "extra", "--config", cfg} },
			wantErr: "unknown command",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newVaultStub(t, tc.opts)
			cfg := tc.config(t, srv.URL)
			args := []string{"ca", "--config", cfg}
			if tc.args != nil {
				args = tc.args(cfg)
			}

			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)

			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero (stdout %q)", stdout.String())
			}
			// A half-written PEM would be spliced into the catalog.
			if stdout.Len() != 0 {
				t.Errorf("stdout must stay empty on failure, got %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

// A bare invocation at a terminal is a human asking what this is: print help
// and exit zero rather than failing on the missing positional.
func TestRunNoArgsOnATerminalPrintsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWith([]string{}, &stdout, &stderr, true); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("stdout = %q, want the help text", stdout.String())
	}
	if !strings.Contains(stdout.String(), "certmanager <common_name>") {
		t.Errorf("help does not document the positional form: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// generate() splices stderr into stdout and reads the result as JSON, so an
// argv that lost its common name must fail loudly with nothing on stdout.
func TestRunNoArgsWithoutATerminalFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWith([]string{}, &stdout, &stderr, false)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero (stdout %q)", stdout.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "a common name is required") {
		t.Errorf("stderr = %q, want it to name the missing common name", stderr.String())
	}
}

// run() decides interactivity from the real stdout, so a piped stdout must not
// take the help path.
func TestRunNoArgsPipedStdoutFails(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close() }()

	var stderr bytes.Buffer
	code := run([]string{}, w, &stderr)
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero (stdout %q)", out)
	}
	if len(out) != 0 {
		t.Errorf("stdout = %q, want empty", out)
	}
}

// Every stdout a machine caller can hand the binary must read as
// not-a-terminal. /dev/null is the trap: it is a character device, so a stat of
// the file mode calls it a terminal and lets help escape with exit zero.
func TestIsTerminalRejectsNonTerminals(t *testing.T) {
	var buf bytes.Buffer
	if isTerminal(&buf) {
		t.Error("a bytes.Buffer is not a terminal")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })

	regular, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = regular.Close() })

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

	for name, f := range map[string]*os.File{
		"pipe":         w,
		"regular file": regular,
		os.DevNull:     devNull,
		"unix socket":  unixSocket(t),
	} {
		if isTerminal(f) {
			t.Errorf("%s is not a terminal", name)
		}
		// An explicit empty argv, never nil: cobra falls back to os.Args[1:]
		// for a nil one, which under `go test -args foo` would turn this into
		// `certmanager foo` and issue against whatever Vault the host's
		// config resolves to. The stderr assertion is what catches that.
		var stderr bytes.Buffer
		code := run([]string{}, f, &stderr)
		if code == 0 {
			t.Errorf("%s: bare invocation exit code = 0, want non-zero", name)
		}
		if want := "a common name is required"; !strings.Contains(stderr.String(), want) {
			t.Errorf("%s: stderr = %q, want it to contain %q", name, stderr.String(), want)
		}
	}
}

// unixSocket returns a connected unix socket as an *os.File: the stdout a
// caller gets when it wires the binary straight into a service.
func unixSocket(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, conn)
			_ = conn.Close()
		}
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	f, err := conn.(*net.UnixConn).File()
	if err != nil {
		t.Fatalf("socket file: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// --config with an empty value is a malformed call, not a request to resolve.
func TestRunRejectsEmptyConfigFlag(t *testing.T) {
	srv, _ := newVaultStub(t, stubOptions{})
	seedXDGConfig(t, srv.URL)

	for _, args := range [][]string{
		{"host.example.com", "--config", "", "--json"},
		{"ca", "--config", ""},
	} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("%v: exit code = 0, want non-zero (stdout %q)", args, stdout.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("%v: stdout = %q, want empty", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "--config requires a path") {
			t.Errorf("%v: stderr = %q", args, stderr.String())
		}
	}
}

// seedXDGConfig writes a config where DefaultPath() looks first.
func seedXDGConfig(t *testing.T, addr string) {
	t.Helper()
	xdg := t.TempDir()
	dir := filepath.Join(xdg, "certmanager")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "vault:\n  addr: " + addr + "\n  auth_method: approle\n" +
		"  approle_path: approle\n  role_id: test-role-id\n" +
		"  mount_point: pki_int\n  role_name: my-role\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("HOME", t.TempDir())
}

// Puppet passes no --config, so the resolved path has to be used.
func TestRunResolvesConfigWithoutFlag(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	seedXDGConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"host.example.com", "--alt-names", "host", "--expiry-days", "90", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if got.issueBody["common_name"] != "host.example.com" {
		t.Errorf("common_name = %v", got.issueBody["common_name"])
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// The ca subcommand shares the same resolution.
func TestRunCAResolvesConfigWithoutFlag(t *testing.T) {
	srv, got := newVaultStub(t, stubOptions{})
	seedXDGConfig(t, srv.URL)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"ca"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !got.caRequested {
		t.Error("the CA chain endpoint was never called")
	}
}

// With no config anywhere the run fails naming the baked-in path, not a
// home-relative one that could never exist under generate().
func TestRunWithoutAnyConfigNamesTheBakedPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	if code := run([]string{"host.example.com", "--json"}, &stdout, &stderr); code == 0 {
		t.Fatal("exit code = 0, want non-zero")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), config.FallbackPath()) {
		t.Errorf("stderr = %q, want it to name %q", stderr.String(), config.FallbackPath())
	}
}
