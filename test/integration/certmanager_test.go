//go:build integration

// Package integration exercises the certmanager binary end to end against a
// real Vault dev server: real PKI mount, real approle login, real issuance.
package integration

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	pkiMount    = "pki"
	pkiRole     = "puppet"
	approlePath = "approle"
	approleRole = "certmanager"
	policyName  = "certmanager-integration"
	certDomain  = "integration.test"
	shortName   = "certmanager-host"
	commonName  = "host." + certDomain
	altName     = "alias." + certDomain
	ipSAN1      = "127.0.0.1"
	ipSAN2      = "192.0.2.5"
	expiryDays  = 90
)

// The address and token come from CERTMANAGER_IT_* rather than VAULT_ADDR /
// VAULT_TOKEN on purpose: this test mounts and writes to PKI, and a developer
// shell nearly always has VAULT_ADDR pointing at production.
func vaultAddr() string {
	if a := os.Getenv("CERTMANAGER_IT_VAULT_ADDR"); a != "" {
		return strings.TrimRight(a, "/")
	}
	return "http://127.0.0.1:8200"
}

func vaultToken() string {
	if t := os.Getenv("CERTMANAGER_IT_VAULT_TOKEN"); t != "" {
		return t
	}
	return "root"
}

// waitForVault polls sys/health until the server is initialised and unsealed.
func waitForVault(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	url := vaultAddr() + "/v1/sys/health?standbyok=true"
	var last string
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec,noctx // fixed test-local URL
		if err != nil {
			last = err.Error()
		} else {
			code := resp.StatusCode
			_ = resp.Body.Close()
			if code == http.StatusOK {
				return
			}
			last = fmt.Sprintf("HTTP %d", code)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("vault at %s not ready: %s", vaultAddr(), last)
}

// vaultReq performs an authenticated request against the dev server and
// decodes the JSON body. A non-2xx response fails the test unless the error
// body matches one of okErrors (used to make mount/auth enabling idempotent).
func vaultReq(t *testing.T, method, path string, payload any, okErrors ...string) map[string]any {
	t.Helper()

	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload for %s: %v", path, err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, vaultAddr()+"/v1/"+path, body) //nolint:noctx // test helper
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}
	req.Header.Set("X-Vault-Token", vaultToken())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		for _, ok := range okErrors {
			if strings.Contains(string(raw), ok) {
				return nil
			}
		}
		t.Fatalf("%s %s: vault returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// setupVault provisions the PKI mount, issuing role, policy and approle role,
// returning the role_id certmanager will authenticate with.
func setupVault(t *testing.T) string {
	t.Helper()

	vaultReq(t, http.MethodPost, "sys/mounts/"+pkiMount,
		map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}},
		"path is already in use")

	vaultReq(t, http.MethodPost, pkiMount+"/root/generate/internal", map[string]any{
		"common_name": certDomain + " integration CA",
		"ttl":         "87600h",
	})

	vaultReq(t, http.MethodPost, pkiMount+"/roles/"+pkiRole, map[string]any{
		"allowed_domains":    []string{certDomain, shortName},
		"allow_subdomains":   true,
		"allow_bare_domains": true,
		"allow_ip_sans":      true,
		"key_type":           "rsa",
		"key_bits":           2048,
		"max_ttl":            "8760h",
	})

	vaultReq(t, http.MethodPut, "sys/policies/acl/"+policyName, map[string]any{
		"policy": fmt.Sprintf(`path "%s/issue/%s" { capabilities = ["update"] }`, pkiMount, pkiRole),
	})

	vaultReq(t, http.MethodPost, "sys/auth/"+approlePath,
		map[string]any{"type": "approle"}, "path is already in use")

	// Mirrors the production role: bind_secret_id false (role_id alone logs in)
	// with token_bound_cidrs as the required constraint.
	vaultReq(t, http.MethodPost, fmt.Sprintf("auth/%s/role/%s", approlePath, approleRole), map[string]any{
		"bind_secret_id":    false,
		"token_bound_cidrs": []string{"0.0.0.0/0"},
		"token_policies":    []string{policyName},
		"token_ttl":         "10m",
	})

	out := vaultReq(t, http.MethodGet, fmt.Sprintf("auth/%s/role/%s/role-id", approlePath, approleRole), nil)
	data, _ := out["data"].(map[string]any)
	roleID, _ := data["role_id"].(string)
	if roleID == "" {
		t.Fatal("vault returned an empty approle role_id")
	}
	return roleID
}

// buildBinary compiles certmanager with the config path baked in, so the test
// can invoke it with exactly the argv Puppet's generate() uses -- no --config.
func buildBinary(t *testing.T, dir, configPath string) string {
	t.Helper()

	bin := filepath.Join(dir, "certmanager")
	ldflags := fmt.Sprintf("-s -w -X main.version=integration -X github.com/IUCLabs/certmanager/internal/config.defaultPath=%s", configPath)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags="+ldflags, "-o", bin, "./cmd/certmanager")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build certmanager: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

func writeConfig(t *testing.T, dir, roleID string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`vault:
  addr: %s
  auth_method: approle
  approle_path: %s
  role_id: %s
  mount_point: %s
  role_name: %s
  output_path: %s
`, vaultAddr(), approlePath, roleID, pkiMount, pkiRole, dir)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func runCertmanager(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %s: %v", bin, err)
		}
		code = exitErr.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

func TestIssueCertificateAgainstVault(t *testing.T) {
	waitForVault(t)
	roleID := setupVault(t)

	dir := t.TempDir()
	cfg := writeConfig(t, dir, roleID)
	bin := buildBinary(t, dir, cfg)

	// Exactly the argv profiles::pki::vault passes to generate().
	code, stdout, stderr := runCertmanager(t, bin,
		commonName,
		"--alt-names", shortName+","+altName,
		"--ip-sans", ipSAN1+","+ipSAN2,
		"--expiry-days", fmt.Sprint(expiryDays),
		"--json",
	)

	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	// generate() runs with combine: true, splicing stderr into the stdout that
	// parsejson() reads -- a single byte on stderr breaks the catalog compile.
	if stderr != "" {
		t.Errorf("stderr must be empty on success, got %q", stderr)
	}

	var doc map[string]string
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	for _, key := range []string{"certificate", "private_key", "full_chain", "ca_certificate"} {
		if doc[key] == "" {
			t.Errorf("JSON key %q is missing or empty", key)
		}
	}

	cert := parseCert(t, doc["certificate"])
	if cert.Subject.CommonName != commonName {
		t.Errorf("certificate CN = %q, want %q", cert.Subject.CommonName, commonName)
	}
	for _, want := range []string{shortName, altName} {
		if !slices.Contains(cert.DNSNames, want) {
			t.Errorf("certificate DNS SANs %v missing %q", cert.DNSNames, want)
		}
	}
	for _, want := range []string{ipSAN1, ipSAN2} {
		if !containsIP(cert.IPAddresses, want) {
			t.Errorf("certificate IP SANs %v missing %q", cert.IPAddresses, want)
		}
	}

	// Proves the "<days>d" TTL string is understood by a real Vault.
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime < 89*24*time.Hour || lifetime > 91*24*time.Hour {
		t.Errorf("certificate lifetime %v, want ~%dd", lifetime, expiryDays)
	}

	ca := parseCert(t, doc["ca_certificate"])
	if !ca.IsCA {
		t.Errorf("ca_certificate is not a CA certificate")
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		t.Errorf("certificate is not signed by ca_certificate: %v", err)
	}
	if !strings.Contains(doc["full_chain"], strings.TrimSpace(doc["certificate"])) ||
		!strings.Contains(doc["full_chain"], strings.TrimSpace(doc["ca_certificate"])) {
		t.Errorf("full_chain does not contain both the leaf and the issuing CA")
	}
}

func TestRefusedNameFailsCleanly(t *testing.T) {
	waitForVault(t)
	roleID := setupVault(t)

	dir := t.TempDir()
	cfg := writeConfig(t, dir, roleID)
	bin := buildBinary(t, dir, cfg)

	code, stdout, stderr := runCertmanager(t, bin,
		"nope.example.com",
		"--alt-names", "",
		"--ip-sans", "",
		"--expiry-days", fmt.Sprint(expiryDays),
		"--json",
	)

	if code == 0 {
		t.Fatalf("expected a non-zero exit for a refused name, stdout: %s", stdout)
	}
	// A half-written JSON document would break parsejson() in the catalog.
	if stdout != "" {
		t.Errorf("stdout must be empty on failure, got %q", stdout)
	}
	if !strings.Contains(stderr, "certmanager:") {
		t.Errorf("stderr should carry the cause, got %q", stderr)
	}
}

func parseCert(t *testing.T, data string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		t.Fatalf("not a PEM document: %s", data)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func containsIP(haystack []net.IP, needle string) bool {
	want := net.ParseIP(needle)
	for _, v := range haystack {
		if v.Equal(want) {
			return true
		}
	}
	return false
}
