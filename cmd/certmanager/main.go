package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/pki"
	"github.com/IUCLabs/certmanager/internal/ssh"
	"github.com/IUCLabs/certmanager/internal/vault"
)

var cfgFile string

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "certmanager",
		Short: "Request PKI certificates and sign SSH host keys via HashiCorp Vault",
	}
	root.PersistentFlags().StringVar(&cfgFile, "config", config.DefaultPath(), "path to config.yaml")

	root.AddCommand(pkiCmd())
	root.AddCommand(sshCmd())
	return root
}

// ---------------------------------------------------------------------------
// pki subcommand
// ---------------------------------------------------------------------------

func pkiCmd() *cobra.Command {
	var (
		altNames   []string
		ipSans     []string
		expiryDays int
		jsonOut    bool
	)

	cmd := &cobra.Command{
		Use:   "pki <common_name>",
		Short: "Issue a PKI certificate from Vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			commonName := args[0]

			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			client, err := vault.New(cfg.Vault)
			if err != nil {
				return fmt.Errorf("vault auth: %w", err)
			}

			cert, err := pki.IssueCert(client, cfg.Vault.MountPoint, cfg.Vault.RoleName, commonName, altNames, ipSans, expiryDays)
			if err != nil {
				return fmt.Errorf("issue cert: %w", err)
			}

			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(cert)
			}

			outDir := cfg.Vault.OutputPath
			if outDir == "" {
				outDir = "."
			}
			return writePKIFiles(outDir, commonName, cert)
		},
	}

	cmd.Flags().StringSliceVar(&altNames, "alt-names", nil, "additional DNS SANs (comma-separated or repeated flag)")
	cmd.Flags().StringSliceVar(&ipSans, "ip-sans", nil, "additional IP SANs (comma-separated or repeated flag)")
	cmd.Flags().IntVar(&expiryDays, "expiry-days", 90, "certificate TTL in days")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print certificate data as JSON instead of writing files")

	return cmd
}

func writePKIFiles(outDir, commonName string, cert *pki.CertificateResponse) error {
	dir := fmt.Sprintf("%s/%s", outDir, commonName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	files := map[string]string{
		"certificate.crt":    cert.Certificate,
		"private.key":        cert.PrivateKey,
		"full_chain.crt":     cert.FullChain,
		"ca_certificate.crt": cert.CACertificate,
		"certificate.pem":    cert.Certificate + "\n" + cert.PrivateKey,
	}

	for name, content := range files {
		mode := os.FileMode(0o644)
		if name == "private.key" || name == "certificate.pem" {
			mode = 0o600
		}
		path := fmt.Sprintf("%s/%s", dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ssh subcommand
// ---------------------------------------------------------------------------

func sshCmd() *cobra.Command {
	var (
		publicKey  string
		principals []string
		ttl        string
		jsonOut    bool
	)

	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Sign an SSH host public key via Vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			client, err := vault.New(cfg.Vault)
			if err != nil {
				return fmt.Errorf("vault auth: %w", err)
			}

			// Flatten any comma-separated values passed as a single string
			var flatPrincipals []string
			for _, p := range principals {
				for _, part := range strings.Split(p, ",") {
					if s := strings.TrimSpace(part); s != "" {
						flatPrincipals = append(flatPrincipals, s)
					}
				}
			}

			signed, err := ssh.SignHostCert(client, cfg.Vault.MountPoint, cfg.Vault.RoleName, publicKey, flatPrincipals, ttl)
			if err != nil {
				return fmt.Errorf("sign ssh cert: %w", err)
			}

			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(signed)
			}

			fmt.Print(signed.SignedKey)
			return nil
		},
	}

	cmd.Flags().StringVar(&publicKey, "public-key", "", "SSH public key string (e.g. \"ssh-rsa AAAA...\")")
	cmd.Flags().StringSliceVar(&principals, "valid-principals", nil, "principals to embed in the certificate (comma-separated or repeated flag)")
	cmd.Flags().StringVar(&ttl, "ttl", "87600h", "certificate TTL (e.g. 87600h)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print signed key as JSON instead of plain text")
	_ = cmd.MarkFlagRequired("public-key")
	_ = cmd.MarkFlagRequired("valid-principals")

	return cmd
}
