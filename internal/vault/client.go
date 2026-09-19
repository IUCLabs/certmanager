package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/IUCLabs/certmanager/internal/config"
)

// maxErrorBody caps how much of a Vault error response is quoted back.
const maxErrorBody = 2048

// Client is an authenticated Vault HTTP client.
type Client struct {
	addr  string
	token string
	http  *http.Client
}

// New authenticates to Vault using the method named in cfg and returns a ready
// Client. An unknown method, or a failure of the selected method, is an error:
// there is no fallback between methods.
func New(cfg config.VaultConfig) (*Client, error) {
	timeout, err := cfg.RequestTimeout()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify()}, //nolint:gosec // defaults to the Python script's verify=False; flip vault.tls_skip_verify to enable
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}

	c := &Client{
		addr: strings.TrimRight(cfg.Addr, "/"),
		http: &http.Client{Transport: transport, Timeout: timeout},
	}

	switch cfg.AuthMethod {
	case config.AuthMethodAppRole:
		err = c.loginAppRole(cfg)
	case config.AuthMethodKubernetes:
		err = c.loginKubernetes(cfg)
	default:
		return nil, fmt.Errorf("unknown vault.auth_method %q (valid: %s, %s)",
			cfg.AuthMethod, config.AuthMethodAppRole, config.AuthMethodKubernetes)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) loginAppRole(cfg config.VaultConfig) error {
	// The Vault role sets bind_secret_id: false, so role_id alone logs in.
	payload := map[string]string{"role_id": cfg.RoleID}
	token, err := c.fetchToken(fmt.Sprintf("auth/%s/login", cfg.ApprolePath), payload)
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	c.token = token
	return nil
}

func (c *Client) loginKubernetes(cfg config.VaultConfig) error {
	raw, err := os.ReadFile(cfg.JWTPath)
	if err != nil {
		return fmt.Errorf("kubernetes login: read service account token %q: %w", cfg.JWTPath, err)
	}
	jwt := strings.TrimSpace(string(raw))
	if jwt == "" {
		return fmt.Errorf("kubernetes login: service account token %q is empty", cfg.JWTPath)
	}

	payload := map[string]string{"role": cfg.K8sRole, "jwt": jwt}
	token, err := c.fetchToken(fmt.Sprintf("auth/%s/login", cfg.K8sMount), payload)
	if err != nil {
		return fmt.Errorf("kubernetes login: %w", err)
	}
	c.token = token
	return nil
}

// fetchToken posts to a Vault auth endpoint and extracts the client token.
func (c *Client) fetchToken(authPath string, payload any) (string, error) {
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := c.post(authPath, "", payload, &result); err != nil {
		return "", err
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault returned no auth.client_token")
	}
	return result.Auth.ClientToken, nil
}

// Post sends an authenticated POST to a Vault path and decodes the response.
func (c *Client) Post(path string, payload, out any) error {
	return c.post(path, c.token, payload, out)
}

func (c *Client) post(path, token string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/%s", c.addr, path)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return fmt.Errorf("POST %s: vault returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(detail)))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("POST %s: decode response: %w", path, err)
	}
	return nil
}
