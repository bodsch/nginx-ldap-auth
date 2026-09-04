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

.PHONY: all build test test-race integration cover lint vet vuln fmt tidy check install clean

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

# The integration suite needs a GLAuth binary. It skips without one, so this
# target adds GOPATH/bin to PATH and says what to install if it is still not
# found. The Redis assertions run against an in-process RESP server; point them
# at a real one with NGINX_LDAP_AUTH_REDIS_ADDR.
integration:
	@command -v glauth >/dev/null 2>&1 || test -x "$(shell go env GOPATH)/bin/glauth" || \
		echo "note: glauth not found; install it with 'go install github.com/glauth/glauth/v2@latest'"
	PATH="$(shell go env GOPATH)/bin:$$PATH" go test -race -run Integration -count=1 ./internal/ldap/

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
check: vet test-race integration lint

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
