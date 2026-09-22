// Package integration holds the end-to-end tests that run against a real Vault
// dev server. Those tests are behind the `integration` build tag; the
// subprocess environment they share, and its own test, are not, so a plain
// `go test ./...` still guards the helper the tagged tests depend on.
package integration
