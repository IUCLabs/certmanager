package integration

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// hermeticEnv strips the developer's environment from the subprocess. The
// tests claim to exercise the baked-in config path, so a real
// ~/.config/certmanager/config.yaml must not resolve ahead of it and point the
// binary at a production Vault.
func hermeticEnv(t *testing.T) []string {
	t.Helper()
	empty := t.TempDir()
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + empty,
		"XDG_CONFIG_HOME=" + empty,
	}
}

// Neither leg of the resolution order announces itself when it is missing: an
// unset HOME or XDG_CONFIG_HOME silently falls through to whatever the
// developer has. Both must therefore be set to somewhere empty, not dropped.
// Setting them is not enough either: the env has to replace the ambient one
// rather than extend it, so anything the developer exported is asserted gone.
func TestHermeticEnvSetsBothConfigLegs(t *testing.T) {
	t.Setenv("CERTMANAGER_AMBIENT_MARKER", "leaked")
	t.Setenv("HOME", filepath.Join(t.TempDir(), "developer"))

	env := hermeticEnv(t)

	allowed := []string{"PATH", "HOME", "XDG_CONFIG_HOME"}
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			t.Errorf("%q is not a KEY=VALUE entry", entry)
			continue
		}
		if !slices.Contains(allowed, key) {
			t.Errorf("%s is carried over from the ambient environment; want only %v", key, allowed)
		}
	}

	for _, key := range []string{"HOME=", "XDG_CONFIG_HOME="} {
		idx := slices.IndexFunc(env, func(e string) bool { return strings.HasPrefix(e, key) })
		if idx < 0 {
			t.Fatalf("%s is unset in the subprocess env: %v", key, env)
		}
		dir := strings.TrimPrefix(env[idx], key)
		if !filepath.IsAbs(dir) {
			t.Errorf("%s%s is not an absolute path", key, dir)
		}
		if ambient := os.Getenv(strings.TrimSuffix(key, "=")); ambient != "" && dir == ambient {
			t.Errorf("%s%s is the ambient value, not a scratch directory", key, dir)
		}
		for _, rel := range []string{"certmanager/config.yaml", ".config/certmanager/config.yaml"} {
			if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
				t.Errorf("%s%s already holds %s", key, dir, rel)
			}
		}
	}
}
