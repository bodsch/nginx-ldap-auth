BINARY      := nginx-ldap-auth
CMD         := ./cmd/nginx-ldap-auth
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
UNITDIR     ?= /usr/lib/systemd/system

# CGO is off deliberately: it is what makes MemoryDenyWriteExecute=true in the
# systemd unit safe, and it keeps the binary portable across the distributions
# that might install it.
GOFLAGS  := -trimpath
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: all build test test-race cover lint vet vuln fmt tidy check install clean

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	golangci-lint run

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

# What CI runs, and what to run before pushing.
check: vet test-race lint

install: build
	install -Dm0755 bin/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -Dm0644 systemd/$(BINARY).service $(DESTDIR)$(UNITDIR)/$(BINARY).service
	install -Dm0640 config.example.yaml $(DESTDIR)$(SYSCONFDIR)/$(BINARY)/config.yaml
	install -dm0750 $(DESTDIR)$(SYSCONFDIR)/$(BINARY)
	@echo
	@echo "Generate the cache pepper before starting the service:"
	@echo "  openssl rand -hex 32 > $(SYSCONFDIR)/$(BINARY)/cache-pepper.secret"
	@echo "  chmod 0640 $(SYSCONFDIR)/$(BINARY)/cache-pepper.secret"

clean:
	rm -rf bin dist coverage.out
