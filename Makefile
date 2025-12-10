# === VARIABLES ===
APP_NAME := credo
PKG := ./...
MAIN := ./cmd/server/main.go

# === DEFAULT ===
default: dev

.PHONY: default build run test test-cover test-one e2e e2e-normal e2e-security e2e-report e2e-clean lint fmt imports openapi-lint openapi-build clean docker-clean help

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

# === DOCKER CLEANUP ===
docker-clean:
	@echo "Stopping and removing docker-compose services, images, and volumes for $(APP_NAME)..."
	docker compose down --rmi local --volumes --remove-orphans

docker-demo:
	docker compose --env-file .env.demo -f docker-compose.yml -f docker-compose.demo.yml up --build

# === E2E TESTS ===
e2e:
	@echo "Running E2E tests with godog..."
	@cd e2e && go test -v 

e2e-normal:
	@echo "Running normal flow E2E tests..."
	@cd e2e && go test -v --godog.tags=@normal

e2e-security:
	@echo "Running security simulation tests..."
	@cd e2e && go test -v --godog.tags=@security

e2e-report:
	@echo "Running E2E tests with JSON report..."
	@cd e2e && go test -v --godog.format=cucumber:reports/cucumber.json
	@echo "Report generated at: e2e/reports/cucumber.json"

e2e-clean:
	@echo "Cleaning E2E test artifacts..."
	cd e2e && rm -rf reports

# === OPENAPI ===
openapi-lint:
	@if command -v npx >/dev/null 2>&1; then \
		echo "Linting OpenAPI specs..."; \
		npx @redocly/cli@1.12.0 lint 'docs/openapi/*.yaml'; \
	else \
		echo "npx not found. Install Node.js to lint OpenAPI specs."; \
		exit 1; \
	fi

openapi-build:
	@if command -v npx >/dev/null 2>&1; then \
		echo "Building OpenAPI documentation..."; \
		npx @redocly/cli@1.12.0 build-docs docs/openapi/auth.yaml -o docs/openapi/auth.html; \
		npx @redocly/cli@1.12.0 build-docs docs/openapi/consent.yaml -o docs/openapi/consent.html; \
		echo "Documentation built:"; \
		echo "  - docs/openapi/auth.html"; \
		echo "  - docs/openapi/consent.html"; \
	else \
		echo "npx not found. Install Node.js to build OpenAPI docs."; \
		exit 1; \
	fi

# === HELP ===
help:
	@echo "Available targets:"
	@echo "  build        Build the binary"
	@echo "  run          Run the server"
	@echo "  test         Run all tests"
	@echo "  test-cover   Run tests with coverage"
	@echo "  test-one     Run a single test (use: make test-one t=TestName)"
	@echo "  e2e          Run E2E tests with godog"
	@echo "  e2e-normal   Run only normal flow E2E tests"
	@echo "  e2e-security Run only security simulation tests"
	@echo "  e2e-report   Run E2E tests and generate JSON report"
	@echo "  e2e-clean    Clean E2E test artifacts"
	@echo "  openapi-lint Lint OpenAPI specifications"
	@echo "  openapi-build Build OpenAPI HTML documentation"
	@echo "  lint         Run golangci-lint if available"
	@echo "  fmt          Format code and run vet"
	@echo "  imports      Fix import ordering (goimports)"
	@echo "  clean        Remove build artifacts"
	@echo "  docker-clean Stop containers and remove images/volumes for this app"
	@echo "  help         Show this help"
