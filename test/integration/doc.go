// Package integration holds the end-to-end tests that run against a real Vault
// dev server. The tests are behind the `integration` build tag; this file
// keeps the package buildable for a plain `go test ./...`, which otherwise
// fails on a package whose files are all excluded by build constraints.
package integration
