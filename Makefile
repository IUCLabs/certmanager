BINARY    := certmanager
CMD       := ./cmd/certmanager
GOFLAGS   := -trimpath
LDFLAGS   := -s -w

.PHONY: all build test lint clean install

all: build

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	go test ./...

test-verbose:
	go test -v ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)

install:
	go install $(GOFLAGS) -ldflags "$(LDFLAGS)" $(CMD)

tidy:
	go mod tidy
