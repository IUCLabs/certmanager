package pki

import (
	"fmt"
	"strings"

	"github.com/IUCLabs/certmanager/internal/vault"
)

// CertificateResponse is the JSON-serialisable output returned to callers.
type CertificateResponse struct {
	Certificate    string `json:"certificate"`
	PrivateKey     string `json:"private_key"`
	FullChain      string `json:"full_chain"`
	CACertificate  string `json:"ca_certificate"`
}

type issueRequest struct {
	CommonName string `json:"common_name"`
	AltNames   string `json:"alt_names,omitempty"`
	IPSans     string `json:"ip_sans,omitempty"`
	TTL        string `json:"ttl"`
}

type issueResponse struct {
	Data struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
		IssuingCA   string `json:"issuing_ca"`
	} `json:"data"`
}

// IssueCert requests a PKI certificate from Vault.
func IssueCert(client *vault.Client, mountPoint, roleName, commonName string, altNames, ipSans []string, expiryDays int) (*CertificateResponse, error) {
	req := issueRequest{
		CommonName: commonName,
		TTL:        fmt.Sprintf("%dd", expiryDays),
	}
	if len(altNames) > 0 {
		req.AltNames = strings.Join(altNames, ",")
	}
	if len(ipSans) > 0 {
		req.IPSans = strings.Join(ipSans, ",")
	}

	var resp issueResponse
	path := fmt.Sprintf("%s/issue/%s", mountPoint, roleName)
	if err := client.Post(path, req, &resp); err != nil {
		return nil, err
	}

	fullChain := resp.Data.IssuingCA + "\n" + resp.Data.Certificate

	return &CertificateResponse{
		Certificate:   resp.Data.Certificate,
		PrivateKey:    resp.Data.PrivateKey,
		FullChain:     fullChain,
		CACertificate: resp.Data.IssuingCA,
	}, nil
}
