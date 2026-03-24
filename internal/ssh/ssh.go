package ssh

import (
	"fmt"
	"strings"

	"github.com/IUCLabs/certmanager/internal/vault"
)

// SignedCertResponse is the JSON-serialisable output returned to callers.
type SignedCertResponse struct {
	SignedKey string `json:"signed_key"`
}

type signRequest struct {
	CertType        string `json:"cert_type"`
	PublicKey       string `json:"public_key"`
	ValidPrincipals string `json:"valid_principals"`
	TTL             string `json:"ttl"`
}

type signResponse struct {
	Data struct {
		SignedKey string `json:"signed_key"`
	} `json:"data"`
}

// SignHostCert signs an SSH host public key via the Vault SSH secrets engine.
func SignHostCert(client *vault.Client, mountPoint, roleName, publicKey string, principals []string, ttl string) (*SignedCertResponse, error) {
	if ttl == "" {
		ttl = "87600h"
	}

	req := signRequest{
		CertType:        "host",
		PublicKey:       publicKey,
		ValidPrincipals: strings.Join(principals, ","),
		TTL:             ttl,
	}

	var resp signResponse
	path := fmt.Sprintf("%s/sign/%s", mountPoint, roleName)
	if err := client.Post(path, req, &resp); err != nil {
		return nil, err
	}

	if resp.Data.SignedKey == "" {
		return nil, fmt.Errorf("vault returned empty signed_key")
	}

	return &SignedCertResponse{SignedKey: resp.Data.SignedKey}, nil
}
