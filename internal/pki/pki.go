package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/IUCLabs/certmanager/internal/vault"
)

// CertificateResponse is the JSON document printed with --json and consumed by
// parsejson() in profiles::pki::vault. Field order fixes the key order.
type CertificateResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	FullChain   string `json:"full_chain"`
}

type issueRequest struct {
	CommonName string `json:"common_name"`
	AltNames   string `json:"alt_names"`
	IPSans     string `json:"ip_sans"`
	TTL        string `json:"ttl"`
}

type issueResponse struct {
	Data struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
		IssuingCA   string `json:"issuing_ca"`
	} `json:"data"`
}

// IssueCert requests a certificate from the Vault PKI role.
func IssueCert(client *vault.Client, mountPoint, roleName, commonName string, altNames, ipSans []string, expiryDays int) (*CertificateResponse, error) {
	req := issueRequest{
		CommonName: commonName,
		AltNames:   strings.Join(altNames, ","),
		IPSans:     strings.Join(ipSans, ","),
		TTL:        fmt.Sprintf("%dd", expiryDays),
	}

	var resp issueResponse
	if err := client.Post(fmt.Sprintf("%s/issue/%s", mountPoint, roleName), req, &resp); err != nil {
		return nil, err
	}
	if resp.Data.Certificate == "" || resp.Data.PrivateKey == "" {
		return nil, fmt.Errorf("vault returned no certificate data for %q", commonName)
	}

	// Leaf first: every TLS server that reads full_chain.crt expects the end
	// entity certificate ahead of the issuers.
	return &CertificateResponse{
		Certificate: resp.Data.Certificate,
		PrivateKey:  resp.Data.PrivateKey,
		FullChain:   resp.Data.Certificate + "\n" + resp.Data.IssuingCA,
	}, nil
}

// FetchCAChain returns the mount's CA chain as PEM. /ca_chain is public and
// estate-wide: it needs no token, no role and no per-node context, which is why
// it is fetched here rather than derived from an issue response. It carries the
// root as well as the intermediate, so the result stands alone as a CAfile for
// path builders that insist on a self-signed anchor.
func FetchCAChain(client *vault.Client, mountPoint string) (string, error) {
	path := fmt.Sprintf("%s/ca_chain", mountPoint)
	body, err := client.Get(path)
	if err != nil {
		return "", err
	}

	// The endpoint advertises application/pkix-cert while serving PEM, so the
	// body is parsed rather than sniffed.
	chain := strings.TrimSpace(string(body))
	if chain == "" {
		return "", fmt.Errorf("GET %s: vault returned an empty CA chain", path)
	}
	n, err := countCertificates(chain)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", path, err)
	}
	if n == 0 {
		return "", fmt.Errorf("GET %s: response is not a PEM certificate chain", path)
	}
	return chain + "\n", nil
}

func countCertificates(chain string) (int, error) {
	rest := []byte(chain)
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return count, nil
		}
		if block.Type != "CERTIFICATE" {
			return 0, fmt.Errorf("PEM block %d is a %q, not a CERTIFICATE", count+1, block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return 0, fmt.Errorf("parse certificate %d: %w", count+1, err)
		}
		count++
	}
}
