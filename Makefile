BINARY  := certmanager
CMD     := ./cmd/certmanager
DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Puppet writes the config here (profiles::helpers::certmanager); override to
# bake a different path into the binary.
CONFIG_PATH ?= /opt/certmanager/config.yaml
CONFIG_PKG  := github.com/IUCLabs/certmanager/internal/config
GOFLAGS := -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X $(CONFIG_PKG).defaultPath=$(CONFIG_PATH)"
OS      ?= $(shell go env GOOS)
ARCH    ?= $(shell go env GOARCH)

.PHONY: all build test integration-test lint fmt pre-commit clean install completions release-snapshot patch minor major

all: build

build:
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build $(GOFLAGS) -o $(DIST)/$(BINARY) $(CMD)

test:
	go test -v -race ./...

# End-to-end test against a real Vault dev server (docker/podman locally, the
# Woodpecker `vault` service in CI). Set VAULT_ADDR to use an existing server.
integration-test:
	./scripts/integration-test.sh

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

pre-commit:
	uvx pre-commit run --all-files

clean:
	rm -rf $(DIST) $(BINARY)

install:
	go install $(GOFLAGS) $(CMD)

# Generate bash/zsh/fish completions into dist/completions.
completions: build
	@mkdir -p $(DIST)/completions
	$(DIST)/$(BINARY) completion bash > $(DIST)/completions/$(BINARY).bash
	$(DIST)/$(BINARY) completion zsh  > $(DIST)/completions/_$(BINARY)
	$(DIST)/$(BINARY) completion fish > $(DIST)/completions/$(BINARY).fish

# Build every release artifact (binaries, tar.gz, RPM) locally without
# publishing. goreleaser is the single driver for the tagged release too.
release-snapshot:
	goreleaser release --snapshot --clean

DEFAULT_BRANCH ?= main

# Draft the release with generated notes, then push the tag; the release
# workflow attaches assets to the draft and publishes it.
patch minor major:
	@git fetch --quiet --tags origin $(DEFAULT_BRANCH)
	@test "$$(git branch --show-current)" = "$(DEFAULT_BRANCH)" || { echo "ERROR: not on $(DEFAULT_BRANCH)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "ERROR: working tree not clean"; exit 1; }
	@test "$$(git rev-parse HEAD)" = "$$(git rev-parse origin/$(DEFAULT_BRANCH))" || { echo "ERROR: HEAD is not origin/$(DEFAULT_BRANCH)"; exit 1; }
	@LATEST=$$(git tag --list 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1); \
	NEW=$$(echo "$${LATEST:-v0.0.0}" | sed 's/^v//' | awk -F. -v b=$@ '{ \
		if (b == "major") print "v" ($$1+1) ".0.0"; \
		else if (b == "minor") print "v" $$1 "." ($$2+1) ".0"; \
		else print "v" $$1 "." $$2 "." ($$3+1) }'); \
	SHA=$$(git rev-parse HEAD); \
	gh release create "$$NEW" --draft --target "$$SHA" --generate-notes --title "$$NEW" || exit 1; \
	git push origin "$$SHA:refs/tags/$$NEW" || { gh release delete "$$NEW" --yes; exit 1; }
