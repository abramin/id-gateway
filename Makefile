# === VARIABLES ===
APP_NAME := id-gateway
PKG := ./...
MAIN := ./cmd/server/main.go

# === DEFAULT ===
default: dev

.PHONY: default build run test test-cover test-one lint fmt imports clean help

# === BUILD ===
build:
	go build -o bin/$(APP_NAME) $(MAIN)

run:
	go run $(MAIN)

# === TESTING ===
test:
	go test $(PKG)

test-cover:
	go test -cover $(PKG)

test-one:
	@if [ -z "$(t)" ]; then \
		echo 'Usage: make test-one t=TestName'; \
	else \
		go test -run "$(t)" $(PKG); \
	fi

# === LINT ===
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# === FORMATTING ===
fmt:
	go fmt $(PKG)
	go vet $(PKG)

imports:
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "goimports not installed. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

# === CLEAN ===
clean:
	rm -rf bin/

# === HELP ===
help:
	@echo "Available targets:"
	@echo "  build        Build the binary"
	@echo "  run          Run the server"
	@echo "  test         Run all tests"
	@echo "  test-cover   Run tests with coverage"
	@echo "  test-one     Run a single test (use: make test-one t=TestName)"
	@echo "  lint         Run golangci-lint if available"
	@echo "  fmt          Format code and run vet"
	@echo "  imports      Fix import ordering (goimports)"
	@echo "  clean        Remove build artifacts"
	@echo "  help         Show this help"
