package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/IUCLabs/certmanager/internal/config"
	"github.com/IUCLabs/certmanager/internal/pki"
	"github.com/IUCLabs/certmanager/internal/vault"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns the process exit code. On the success path
// it writes nothing to stderr: Puppet's generate() runs this binary with
// combine: true, which splices stderr into the stdout that parsejson() reads.
func run(args []string, stdout, stderr io.Writer) int {
	cmd := rootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(stderr, "certmanager: %v\n", err)
		return 1
	}
	return 0
}

func rootCmd() *cobra.Command {
	var (
		cfgFile    string
		altNames   string
		ipSans     string
		expiryDays int
		compress   bool
		jsonOut    bool
	)

	cmd := &cobra.Command{
		Use:           "certmanager <common_name>",
		Short:         "Issue a PKI certificate from HashiCorp Vault",
		Version:       version,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}

			client, err := vault.New(cfg.Vault)
			if err != nil {
				return err
			}

			cert, err := pki.IssueCert(client, cfg.Vault.MountPoint, cfg.Vault.RoleName,
				args[0], parseList(altNames), parseList(ipSans), expiryDays)
			if err != nil {
				return err
			}

			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), cert)
			}
			return writeFiles(cfg.Vault.OutputPath, args[0], compress, cert)
		},
	}

	// Persistent so the ca subcommand shares it; the positional form keeps
	// parsing --config exactly as before.
	cmd.PersistentFlags().StringVar(&cfgFile, "config", config.DefaultPath(), "path to config.yaml")
	cmd.Flags().StringVarP(&altNames, "alt-names", "a", "", "comma-separated DNS subject alternative names")
	cmd.Flags().StringVarP(&ipSans, "ip-sans", "i", "", "comma-separated IP subject alternative names")
	cmd.Flags().IntVarP(&expiryDays, "expiry-days", "e", 365, "certificate validity in days")
	cmd.Flags().BoolVarP(&compress, "compress", "c", false, "write the certificate, key and chain into a zip file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the certificate data as JSON instead of writing files")

	cmd.AddCommand(caCmd(&cfgFile))

	return cmd
}

// caCmd prints the mount's CA chain. Distributing the CA this way decouples it
// from certificate issuance, so a CA rotation reaches every node on the next
// catalog compile instead of waiting out a 90 day renewal cycle.
func caCmd(cfgFile *string) *cobra.Command {
	var mount string

	cmd := &cobra.Command{
		Use:           "ca",
		Short:         "Print the PKI mount's CA chain (intermediate and root) as PEM",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.LoadCA(*cfgFile)
			if err != nil {
				return err
			}

			mountPoint := cfg.Vault.MountPoint
			if mount != "" {
				mountPoint = mount
			}
			if mountPoint == "" {
				return fmt.Errorf("vault.mount_point is required (or pass --mount)")
			}

			client, err := vault.NewUnauthenticated(cfg.Vault)
			if err != nil {
				return err
			}

			// The chain is fully validated before a byte reaches stdout: a
			// half-written document would break the catalog compile.
			chain, err := pki.FetchCAChain(client, mountPoint)
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), chain)
			return err
		},
	}

	cmd.Flags().StringVarP(&mount, "mount", "m", "", "PKI mount to read (default: vault.mount_point)")

	return cmd
}

// parseList splits a comma-separated flag value, trimming whitespace and
// dropping empty tokens.
func parseList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func writeJSON(w io.Writer, cert *pki.CertificateResponse) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(cert)
}

// writeFiles is the non-JSON path. outputPath comes from vault.output_path in
// the config; the Python read it from the wrong nesting level so it never
// resolved and always fell back to the working directory.
func writeFiles(outputPath, commonName string, compress bool, cert *pki.CertificateResponse) error {
	if outputPath == "" {
		outputPath = "."
	}

	contents := []struct {
		name string
		body string
		mode os.FileMode
	}{
		{"certificate.crt", cert.Certificate, 0o644},
		{"private.key", cert.PrivateKey, 0o600},
		{"full_chain.crt", cert.FullChain, 0o644},
	}

	if compress {
		zipPath := filepath.Join(outputPath, commonName+".zip")
		if err := os.MkdirAll(outputPath, 0o755); err != nil {
			return fmt.Errorf("create %q: %w", outputPath, err)
		}
		f, err := os.OpenFile(zipPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("create %q: %w", zipPath, err)
		}
		defer func() { _ = f.Close() }()

		zw := zip.NewWriter(f)
		for _, c := range contents {
			w, err := zw.Create(c.name)
			if err != nil {
				return fmt.Errorf("write %s to %q: %w", c.name, zipPath, err)
			}
			if _, err := io.WriteString(w, c.body); err != nil {
				return fmt.Errorf("write %s to %q: %w", c.name, zipPath, err)
			}
		}
		if err := zw.Close(); err != nil {
			return fmt.Errorf("finalise %q: %w", zipPath, err)
		}
		return f.Close()
	}

	dir := filepath.Join(outputPath, commonName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %q: %w", dir, err)
	}
	for _, c := range contents {
		path := filepath.Join(dir, c.name)
		if err := os.WriteFile(path, []byte(c.body), c.mode); err != nil {
			return fmt.Errorf("write %q: %w", path, err)
		}
	}
	return nil
}
