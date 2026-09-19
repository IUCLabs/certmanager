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
	"sync"
	"testing"
	"time"
)

const (
	// Dev-mode Vault has no PKI of its own, and a single root mount would make
	// the CA chain one self-signed certificate -- which would not exercise the
	// intermediate + root shape production serves. So a root mount signs an
	// intermediate, and certificates are issued from the intermediate.
	rootMount   = "pki_root"
	pkiMount    = "pki_int"
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

// setupVault provisions the mounts, issuing role, policy and approle role,
// returning the role_id certmanager will authenticate with. Provisioning runs
// once per process: re-signing the intermediate would add issuers and make the
// mount's CA chain non-deterministic.
func setupVault(t *testing.T) string {
	t.Helper()
	setupOnce.Do(func() { setupRoleID = provisionVault(t) })
	if setupRoleID == "" {
		t.Fatal("vault provisioning failed")
	}
	return setupRoleID
}

var (
	setupOnce   sync.Once
	setupRoleID string
)

func provisionVault(t *testing.T) string {
	t.Helper()

	vaultReq(t, http.MethodPost, "sys/mounts/"+rootMount,
		map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}},
		"path is already in use")
	vaultReq(t, http.MethodPost, "sys/mounts/"+pkiMount,
		map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}},
		"path is already in use")

	root := vaultReq(t, http.MethodPost, rootMount+"/root/generate/internal", map[string]any{
		"common_name": certDomain + " integration root CA",
		"ttl":         "87600h",
		"key_type":    "rsa",
		"key_bits":    2048,
	})
	rootPEM := dataString(t, root, "certificate")

	csr := vaultReq(t, http.MethodPost, pkiMount+"/intermediate/generate/internal", map[string]any{
		"common_name": certDomain + " integration intermediate CA",
		"key_type":    "rsa",
		"key_bits":    2048,
	})

	signed := vaultReq(t, http.MethodPost, rootMount+"/root/sign-intermediate", map[string]any{
		"csr":         dataString(t, csr, "csr"),
		"common_name": certDomain + " integration intermediate CA",
		"ttl":         "43800h",
		"format":      "pem",
	})

	// Appending the root to the signed intermediate is what makes /ca_chain
	// serve both certificates.
	vaultReq(t, http.MethodPost, pkiMount+"/intermediate/set-signed", map[string]any{
		"certificate": dataString(t, signed, "certificate") + "\n" + rootPEM,
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

func dataString(t *testing.T, resp map[string]any, key string) string {
	t.Helper()
	data, _ := resp["data"].(map[string]any)
	v, _ := data[key].(string)
	if v == "" {
		t.Fatalf("vault returned no data.%s", key)
	}
	return v
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
	for _, key := range []string{"certificate", "private_key", "full_chain"} {
		if doc[key] == "" {
			t.Errorf("JSON key %q is missing or empty", key)
		}
	}
	if _, ok := doc["ca_certificate"]; ok {
		t.Error("ca_certificate must not be emitted; the CA comes from the ca subcommand")
	}
	if len(doc) != 3 {
		t.Errorf("document has %d keys, want exactly 3: %v", len(doc), keysOf(doc))
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

	// full_chain is leaf first: asserted as an order, not as membership.
	chain := parseChain(t, doc["full_chain"])
	if len(chain) != 2 {
		t.Fatalf("full_chain carries %d certificates, want leaf + issuing CA", len(chain))
	}
	if !chain[0].Equal(cert) {
		t.Errorf("full_chain starts with %q, want the leaf %q", chain[0].Subject.CommonName, commonName)
	}
	if !chain[1].IsCA {
		t.Errorf("full_chain[1] (%q) is not a CA certificate", chain[1].Subject.CommonName)
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("full_chain is not leaf-then-issuer: %v", err)
	}
}

// TestCAChainAgainstVault is the reason the CA no longer rides along with
// issuance: this runs with no credentials at all.
func TestCAChainAgainstVault(t *testing.T) {
	waitForVault(t)
	roleID := setupVault(t)

	dir := t.TempDir()
	cfg := writeConfig(t, dir, roleID)
	bin := buildBinary(t, dir, cfg)

	code, stdout, stderr := runCertmanager(t, bin, "ca")
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr must be empty on success, got %q", stderr)
	}

	// Puppet reads this through generate() too, so it must be the PEM and
	// nothing else.
	if !strings.HasPrefix(stdout, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("stdout is not a PEM document: %q", stdout)
	}

	chain := parseChain(t, stdout)
	if len(chain) != 2 {
		t.Fatalf("CA chain carries %d certificates, want intermediate + root", len(chain))
	}
	intermediate, root := chain[0], chain[1]

	if !intermediate.IsCA || !root.IsCA {
		t.Errorf("both chain entries must be CA certificates: %v, %v", intermediate.IsCA, root.IsCA)
	}
	// The root anchors the chain: self-issued and self-signed. issuing_ca alone
	// would not be, which is what breaks strict path builders.
	if root.Subject.String() != root.Issuer.String() {
		t.Errorf("chain[1] subject %q != issuer %q, so it is not the root", root.Subject, root.Issuer)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("chain[1] is not self-signed: %v", err)
	}
	if intermediate.Subject.String() == intermediate.Issuer.String() {
		t.Errorf("chain[0] %q is self-issued; expected the intermediate", intermediate.Subject)
	}

	// Issue a leaf and verify it against the chain the ca subcommand returned.
	_, issued, stderr := runCertmanager(t, bin,
		commonName,
		"--alt-names", shortName+","+altName,
		"--ip-sans", ipSAN1+","+ipSAN2,
		"--expiry-days", fmt.Sprint(expiryDays),
		"--json",
	)
	var doc map[string]string
	if err := json.Unmarshal([]byte(issued), &doc); err != nil {
		t.Fatalf("issue stdout is not JSON: %v (stderr %q)", err, stderr)
	}
	leaf := parseCert(t, doc["certificate"])

	if err := leaf.CheckSignatureFrom(intermediate); err != nil {
		t.Errorf("chain[0] did not sign the issued leaf: %v", err)
	}

	// The openssl verify equivalent: anchor on the root, bridge with the
	// intermediate, both taken from the ca output alone.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	inters.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		DNSName:       commonName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("leaf does not validate against the ca chain: %v", err)
	}
}

// The CA chain endpoint is public, so a config with no auth keys must work.
func TestCAChainNeedsNoCredentials(t *testing.T) {
	waitForVault(t)
	roleID := setupVault(t)

	dir := t.TempDir()
	bin := buildBinary(t, dir, writeConfig(t, dir, roleID))

	authless := filepath.Join(dir, "authless.yaml")
	body := fmt.Sprintf("vault:\n  addr: %s\n  mount_point: %s\n", vaultAddr(), pkiMount)
	if err := os.WriteFile(authless, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	code, stdout, stderr := runCertmanager(t, bin, "ca", "--config", authless)
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr must be empty on success, got %q", stderr)
	}
	if len(parseChain(t, stdout)) != 2 {
		t.Errorf("credential-free ca output is not the two certificate chain: %q", stdout)
	}
}

func TestCAChainFailsCleanlyForAnUnknownMount(t *testing.T) {
	waitForVault(t)
	roleID := setupVault(t)

	dir := t.TempDir()
	bin := buildBinary(t, dir, writeConfig(t, dir, roleID))

	code, stdout, stderr := runCertmanager(t, bin, "ca", "--mount", "pki_does_not_exist")
	if code == 0 {
		t.Fatalf("expected a non-zero exit, stdout: %s", stdout)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty on failure, got %q", stdout)
	}
	if !strings.Contains(stderr, "certmanager:") {
		t.Errorf("stderr should carry the cause, got %q", stderr)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func parseChain(t *testing.T, data string) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("PEM block %d is a %q", len(out)+1, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate %d: %v", len(out)+1, err)
		}
		out = append(out, cert)
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
