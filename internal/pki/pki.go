package pki

import (
	"fmt"
	"strings"

	"github.com/IUCLabs/certmanager/internal/vault"
)

// CertificateResponse is the JSON document printed with --json and consumed by
// parsejson() in profiles::pki::vault. Field order fixes the key order.
type CertificateResponse struct {
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"private_key"`
	FullChain     string `json:"full_chain"`
	CACertificate string `json:"ca_certificate"`
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

	return &CertificateResponse{
		Certificate:   resp.Data.Certificate,
		PrivateKey:    resp.Data.PrivateKey,
		FullChain:     resp.Data.IssuingCA + "\n" + resp.Data.Certificate,
		CACertificate: resp.Data.IssuingCA,
	}, nil
}
