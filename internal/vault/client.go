package vault

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/IUCLabs/certmanager/internal/config"
)

const defaultKubernetesTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Client is an authenticated Vault HTTP client.
type Client struct {
	addr  string
	token string
	http  *http.Client
}

// New authenticates to Vault using the method specified in cfg and returns a
// ready Client.
func New(cfg config.VaultConfig) (*Client, error) {
	// TLS verification is intentionally skipped to match the existing Python
	// scripts; the TODO comment in those scripts notes this should be removed
	// once certs are generated everywhere.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	httpClient := &http.Client{Transport: transport}

	c := &Client{addr: cfg.Addr, http: httpClient}

	var err error
	switch cfg.AuthMethod {
	case config.AuthMethodAppRole, "":
		err = c.loginAppRole(cfg)
	case config.AuthMethodLDAP:
		err = c.loginLDAP(cfg)
	case config.AuthMethodKubernetes:
		err = c.loginKubernetes(cfg)
	case config.AuthMethodToken:
		err = c.loginToken(cfg)
	default:
		return nil, fmt.Errorf("unknown auth_method %q (valid: approle, ldap, kubernetes, token)", cfg.AuthMethod)
	}
	if err != nil {
		return nil, err
	}

	return c, nil
}

// ---------------------------------------------------------------------------
// auth method implementations
// ---------------------------------------------------------------------------

func (c *Client) loginAppRole(cfg config.VaultConfig) error {
	path := cfg.ApprolePath
	if path == "" {
		path = "approle"
	}
	payload := map[string]string{"role_id": cfg.RoleID}
	if cfg.SecretID != "" {
		payload["secret_id"] = cfg.SecretID
	}
	token, err := c.fetchToken(fmt.Sprintf("auth/%s/login", path), payload)
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	c.token = token
	return nil
}

func (c *Client) loginLDAP(cfg config.VaultConfig) error {
	path := cfg.LDAPPath
	if path == "" {
		path = "ldap"
	}
	payload := map[string]string{"password": cfg.LDAPPassword}
	token, err := c.fetchToken(fmt.Sprintf("auth/%s/login/%s", path, cfg.LDAPUsername), payload)
	if err != nil {
		return fmt.Errorf("ldap login: %w", err)
	}
	c.token = token
	return nil
}

func (c *Client) loginKubernetes(cfg config.VaultConfig) error {
	path := cfg.KubernetesPath
	if path == "" {
		path = "kubernetes"
	}
	tokenFile := cfg.KubernetesTokenFile
	if tokenFile == "" {
		tokenFile = defaultKubernetesTokenFile
	}
	jwt, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("kubernetes login: read service account token %q: %w", tokenFile, err)
	}
	payload := map[string]string{
		"role": cfg.KubernetesRole,
		"jwt":  string(jwt),
	}
	token, err := c.fetchToken(fmt.Sprintf("auth/%s/login", path), payload)
	if err != nil {
		return fmt.Errorf("kubernetes login: %w", err)
	}
	c.token = token
	return nil
}

func (c *Client) loginToken(cfg config.VaultConfig) error {
	if cfg.Token == "" {
		return fmt.Errorf("token auth: vault.token must not be empty")
	}
	c.token = cfg.Token
	return nil
}

// fetchToken posts to a Vault auth endpoint and extracts the client token.
func (c *Client) fetchToken(authPath string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/v1/%s", c.addr, authPath)
	resp, err := c.http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("empty client token in response")
	}
	return result.Auth.ClientToken, nil
}

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

// Post sends an authenticated POST to a Vault path and decodes the response.
func (c *Client) Post(path string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/%s", c.addr, path)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault POST %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault POST %s: unexpected status %d", path, resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
