# nginx-ldap-auth Makefile
#
# All build/test/quality logic lives here so CI configs stay thin wrappers that
# only invoke `make` targets.
#
# Everything below the variable block follows the house style of the sibling Go
# services (mailcow-netfilter and friends), apart from the service-specific
# targets at the very bottom.

BINARY   := nginx-ldap-auth
CMD_PKG  := ./cmd/nginx-ldap-auth/

# --- shared from here on ------------------------------------------------------

BIN_DIR  := bin
DIST_DIR := dist

# Version metadata, overridable from the environment / CI.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# BUILD_DATE is a UTC day, not a timestamp: it is what the release workflow
# stamps, it keeps two builds of the same release comparable, and it is coarse
# enough not to make an otherwise identical build differ by the second.
BUILD_DATE ?= $(shell date -u +%Y-%m-%d)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

# Static binaries. Not for a container — this service is deployed natively —
# but because it is what makes MemoryDenyWriteExecute=true in the systemd unit
# safe, and what lets one build run on any distribution. The race detector is
# the exception, see the test target.
export CGO_ENABLED := 0

# Linux only. The service is a systemd unit that sits behind nginx; it builds
# and its tests pass on darwin, which is why development there works, but there
# is nothing to ship.
PLATFORMS := linux/amd64 linux/arm64

# Installation paths, matching the PKGBUILD.
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
UNITDIR     ?= /usr/lib/systemd/system
SYSUSERSDIR ?= /usr/lib/sysusers.d
TMPFILESDIR ?= /usr/lib/tmpfiles.d
LICENSEDIR  ?= $(PREFIX)/share/licenses/$(BINARY)
DOCDIR      ?= $(PREFIX)/share/doc/$(BINARY)

GO       := go
GOLANGCI := golangci-lint

.DEFAULT_GOAL := build

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into bin/.
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)

# The race detector requires cgo and a C compiler on every platform except
# darwin, where it also links without one. Overriding CGO_ENABLED here rather
# than dropping the export above keeps the binaries static while letting the
# tests run: without it, `go test -race` fails on Linux with
# "-race requires cgo; enable cgo by setting CGO_ENABLED=1".
.PHONY: test
test: ## Run the test suite with the race detector (needs a C compiler).
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and write a coverage profile.
	CGO_ENABLED=1 $(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1

.PHONY: fmt
fmt: ## Fail if anything is not gofmt-clean.
	@out="$$(gofmt -l cmd internal)"; \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; echo "run 'gofmt -w cmd internal'."; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint (uses .golangci.yml if present).
	@command -v $(GOLANGCI) >/dev/null 2>&1 || { \
		echo "$(GOLANGCI) not found — install it from https://golangci-lint.run/welcome/install/"; \
		exit 1; \
	}
	$(GOLANGCI) run ./...

.PHONY: vuln
vuln: ## Scan deps and reachable code for known vulnerabilities (govulncheck).
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: sec
sec: lint vuln ## Security checks: golangci-lint (incl. gosec) + govulncheck.

.PHONY: tidy
tidy: ## Tidy and verify go.mod/go.sum.
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: ci
ci: fmt vet lint vuln test build ## Full CI pipeline: fmt, vet, lint, vuln, test (race), build.

.PHONY: release
release: ## Cross-compile static release binaries into dist/.
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out=$(DIST_DIR)/$(BINARY)-$$os-$$arch; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$out $(CMD_PKG) || exit 1; \
	done

.PHONY: install
install: build ## Install the binary, unit, sysusers fragment and examples.
	install -Dm0755 $(BIN_DIR)/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -Dm0644 systemd/$(BINARY).service $(DESTDIR)$(UNITDIR)/$(BINARY).service
	install -Dm0644 packaging/$(BINARY).sysusers $(DESTDIR)$(SYSUSERSDIR)/$(BINARY).conf
	install -Dm0644 packaging/$(BINARY).tmpfiles $(DESTDIR)$(TMPFILESDIR)/$(BINARY).conf
	install -Dm0640 config.example.yaml $(DESTDIR)$(SYSCONFDIR)/$(BINARY)/config.yaml
	install -Dm0644 nginx/auth.conf $(DESTDIR)$(DOCDIR)/examples/auth.conf
	install -Dm0644 config.example.yaml $(DESTDIR)$(DOCDIR)/config.example.yaml
	install -Dm0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -Dm0644 project.md $(DESTDIR)$(DOCDIR)/project.md
	install -Dm0644 LICENSE $(DESTDIR)$(LICENSEDIR)/LICENSE

.PHONY: clean
clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out

# --- service specific ---------------------------------------------------------

# The integration suite runs a real GLAuth as a separate process. It is not part
# of `make test` because it needs a binary that is not a module dependency, and
# a developer without it should still get a green run rather than a failure they
# cannot act on. The suite skips with an install hint in that case.
.PHONY: test-integration
test-integration: ## Run the suite against a real GLAuth directory (skips without the binary).
	@command -v glauth >/dev/null 2>&1 || test -x "$(shell $(GO) env GOPATH)/bin/glauth" || \
		echo "note: glauth not found; install it with 'go install github.com/glauth/glauth/v2@latest'"
	PATH="$(shell $(GO) env GOPATH)/bin:$$PATH" CGO_ENABLED=1 \
		$(GO) test -race -count=1 -run Integration ./internal/ldap/

# The pepper must not be generated at package build time: every installation
# would then share one secret, and a leaked cache from any of them would be
# crackable against all the others. This target is what an operator runs once,
# and what the package's post-install hook calls.
.PHONY: pepper
pepper: ## Generate the cache pepper if it does not exist yet.
	@path="$(DESTDIR)$(SYSCONFDIR)/$(BINARY)/cache-pepper.secret"; \
	if [ -f "$$path" ]; then \
		echo "$$path exists, leaving it alone"; \
	else \
		install -dm0750 "$$(dirname "$$path")"; \
		umask 027 && openssl rand -hex 32 > "$$path"; \
		echo "generated $$path"; \
	fi
