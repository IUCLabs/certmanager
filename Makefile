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

.PHONY: all build test integration-test lint fmt pre-commit clean install completions release-snapshot patch minor major _tag

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

# Bump helpers — read the latest semver tag and create the next one.
_LATEST := $(shell git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1)
_BASE   := $(if $(_LATEST),$(_LATEST),v0.0.0)
_MAJ    := $(shell echo $(_BASE) | sed 's/^v//' | cut -d. -f1)
_MIN    := $(shell echo $(_BASE) | sed 's/^v//' | cut -d. -f2)
_PAT    := $(shell echo $(_BASE) | sed 's/^v//' | cut -d. -f3)

patch:
	@NEW=v$(_MAJ).$(_MIN).$(shell expr $(_PAT) + 1); \
	git tag $$NEW && echo "Tagged $$NEW" && $(MAKE) _tag TAG=$$NEW

minor:
	@NEW=v$(_MAJ).$(shell expr $(_MIN) + 1).0; \
	git tag $$NEW && echo "Tagged $$NEW" && $(MAKE) _tag TAG=$$NEW

major:
	@NEW=v$(shell expr $(_MAJ) + 1).0.0; \
	git tag $$NEW && echo "Tagged $$NEW" && $(MAKE) _tag TAG=$$NEW

_tag:
	git push origin $(TAG)
