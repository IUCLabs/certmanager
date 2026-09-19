package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
	issueDelay    time.Duration
}

type capture struct {
	authPath  string
	authBody  map[string]any
	issueBody map[string]any
	token     string
}

func newVaultStub(t *testing.T, opts stubOptions) (*httptest.Server, *capture) {
	t.Helper()
	got := &capture{}

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
		if opts.issueDelay > 0 {
			time.Sleep(opts.issueDelay)
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
		`"full_chain":"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",` +
		`"ca_certificate":"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"}` + "\n"
	if stdout.String() != want {
		t.Errorf("stdout mismatch\n got: %q\nwant: %q", stdout.String(), want)
	}

	// The whole point of --json: parsejson() must be able to read it.
	var parsed map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if parsed["ca_certificate"] != testCA {
		t.Errorf("ca_certificate = %q, want issuing_ca", parsed["ca_certificate"])
	}
	if parsed["full_chain"] != testCA+"\n"+testCert {
		t.Errorf("full_chain = %q", parsed["full_chain"])
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
			opts: stubOptions{issueDelay: 400 * time.Millisecond},
			config: func(t *testing.T, addr string) string {
				return approleConfig(t, addr, "  timeout: 50ms\n")
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
		"certificate.crt":    testCert,
		"private.key":        testKey,
		"full_chain.crt":     testCA + "\n" + testCert,
		"ca_certificate.crt": testCA,
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
	wantNames := []string{"certificate.crt", "private.key", "full_chain.crt", "ca_certificate.crt"}
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
