# === VARIABLES ===
APP_NAME := credo
PKG := ./...
MAIN := ./cmd/server/main.go
PROTO_DIR := api/proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)
TEST_CPUS ?= $(shell (command -v nproc >/dev/null 2>&1 && nproc) || (sysctl -n hw.ncpu 2>/dev/null) || echo 4)
TEST_FLAGS ?= -p $(TEST_CPUS) -parallel $(TEST_CPUS)

# === DEFAULT ===
default: dev

.PHONY: default build run test test-failed test-failures test-cover test-one test-slow e2e e2e-normal e2e-security e2e-simulation e2e-report e2e-clean lint fmt imports openapi-lint openapi-build clean docker-clean docker-reset proto-gen proto-check proto-clean help

# === BUILD ===
build:
	go build -o bin/$(APP_NAME) $(MAIN)

run:
	go run $(MAIN)

# === TESTING ===
test:
	@if command -v gotestsum >/dev/null 2>&1; then \
		FORCE_COLOR=1 TERM=xterm-256color gotestsum --hide-summary=skipped --format testname --no-color=false -- -v $(TEST_FLAGS) $(PKG); \
	else \
		echo "gotestsum not installed, falling back to go test"; \
		go test -v $(TEST_FLAGS) $(PKG); \
	fi

test-cover:
	gotestsum -- -coverprofile=cover.out ./...
	go tool cover -html=cover.out -o cover.html
	@echo "Coverage report: cover.html"

test-one:
	@if [ -z "$(t)" ]; then \
		echo 'Usage: make test-one t=TestName'; \
	else \
		go test -run "$(t)" $(PKG); \
	fi

test-slow:
	@if ! command -v jq >/dev/null 2>&1; then \
		echo "jq not installed. Install with: brew install jq"; \
		exit 1; \
	fi
	@echo "Finding slowest tests (top $(or $(n),10))..."
	@go test -json $(PKG) 2>/dev/null | \
		jq -r 'select(.Action == "pass" and .Test != null and .Elapsed != null) | "\(.Elapsed)\t\(.Package)\t\(.Test)"' | \
		sort -rn | \
		head -$(or $(n),10) | \
		awk 'BEGIN {printf "%-10s %-60s %s\n", "TIME (s)", "PACKAGE", "TEST"; print "---------- ------------------------------------------------------------ ----------"} {printf "%-10.3f %-60s %s\n", $$1, $$2, $$3}'

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

docker-reset: docker-clean

docker-demo:
	docker compose --env-file .env.demo -f docker-compose.yml -f docker-compose.demo.yml up --build

# === E2E TESTS ===
e2e:
	@echo "Running E2E tests with godog (excluding @simulation, @unregulated, @regulated, @pending tests)..."
	@cd e2e && GODOG_TAGS="~@simulation && ~@unregulated && ~@regulated && ~@pending" go test -v

e2e-unregulated:
	@echo "Running unregulated mode E2E tests (requires REGULATED_MODE=false)..."
	@cd e2e && GODOG_TAGS="@unregulated" go test -v

e2e-regulated:
	@echo "Running regulated mode E2E tests (requires REGULATED_MODE=true)..."
	@cd e2e && GODOG_TAGS="@regulated" go test -v

e2e-normal:
	@echo "Running normal flow E2E tests..."
	@cd e2e && GODOG_TAGS="@normal" go test -v

e2e-security:
	@echo "Running security simulation tests..."
	@cd e2e && GODOG_TAGS="@security" go test -v

e2e-simulation:
	@echo "Running simulation tests (requires rate limiting enabled)..."
	@cd e2e && GODOG_TAGS="@simulation" go test -v

e2e-report:
	@echo "Running E2E tests with JSON report..."
	@cd e2e && GODOG_TAGS="~@simulation" go test -v
	@echo "Report generated at: e2e/reports/cucumber.json"

e2e-clean:
	@echo "Cleaning E2E test artifacts..."
	cd e2e && rm -rf reports

# === PROTOBUF ===
proto-gen:
	@echo "Generating Go code from protobuf definitions..."
	@if command -v protoc >/dev/null 2>&1; then \
		protoc \
			--go_out=. \
			--go_opt=paths=source_relative \
			--go-grpc_out=. \
			--go-grpc_opt=paths=source_relative \
			$(PROTO_FILES); \
		echo "Protobuf generation complete."; \
	else \
		echo "protoc not installed. Install with:"; \
		echo "  brew install protobuf  # macOS"; \
		echo "  apt install protobuf-compiler  # Ubuntu"; \
		exit 1; \
	fi

proto-check:
	@echo "Checking if generated proto files are up to date..."
	@git diff --exit-code api/proto/ || (echo "ERROR: Generated proto files are out of date. Run 'make proto-gen'" && exit 1)
	@echo "Proto files are up to date."

proto-clean:
	@echo "Cleaning generated proto files..."
	@find $(PROTO_DIR) -name "*.pb.go" -delete
	@echo "Cleaned generated proto files."

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
		npx @redocly/cli@1.12.0 build-docs docs/openapi/ratelimit.yaml -o docs/openapi/ratelimit.html; \
		echo "Documentation built:"; \
		echo "  - docs/openapi/auth.html"; \
		echo "  - docs/openapi/consent.html"; \
		echo "  - docs/openapi/ratelimit.html"; \
	else \
		echo "npx not found. Install Node.js to build OpenAPI docs."; \
		exit 1; \
	fi

# === DATABASE MIGRATIONS ===
MIGRATE_VERSION := v4.19.1
DATABASE_URL ?= postgres://credo:credo_dev_password@localhost:5432/credo?sslmode=disable
MIGRATIONS_DIR := migrations

.PHONY: migrate-install migrate-up migrate-down migrate-down-all migrate-create migrate-status migrate-force migrate-validate

migrate-install:
	@echo "Installing golang-migrate..."
	@go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@$(MIGRATE_VERSION)

migrate-up:
	@echo "Running migrations..."
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down:
	@echo "Rolling back last migration..."
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-down-all:
	@echo "Rolling back all migrations..."
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down -all

migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "Usage: make migrate-create name=migration_name"; \
		exit 1; \
	fi
	@echo "Creating migration: $(name)"
	@migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(name)

migrate-status:
	@echo "Current migration version:"
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version

migrate-force:
	@if [ -z "$(v)" ]; then \
		echo "Usage: make migrate-force v=VERSION"; \
		exit 1; \
	fi
	@echo "Forcing version to: $(v)"
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" force $(v)

migrate-validate:
	@echo "Validating migration state..."
	@migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" version 2>&1 | grep -q "dirty" && \
		echo "ERROR: Database is in dirty state. Run migrate-force to fix." && exit 1 || \
		echo "Migration state is clean."

# === HELP ===
help:
	@echo "Available targets:"
	@echo "  build          Build the binary"
	@echo "  run            Run the server"
	@echo "  test           Run all tests"
	@echo "  test-failed    Run tests, show only failures (hide skipped)"
	@echo "  test-cover     Run tests with coverage"
	@echo "  test-one       Run a single test (use: make test-one t=TestName)"
	@echo "  test-slow      Find slowest tests (use: make test-slow n=5 for top 5)"
	@echo "  e2e            Run E2E tests with godog (excludes @simulation)"
	@echo "  e2e-normal     Run only normal flow E2E tests"
	@echo "  e2e-security   Run only security simulation tests"
	@echo "  e2e-simulation Run rate limit simulation tests (requires DISABLE_RATE_LIMITING=false)"
	@echo "  e2e-report     Run E2E tests and generate JSON report"
	@echo "  e2e-clean      Clean E2E test artifacts"
	@echo "  proto-gen      Generate Go code from protobuf definitions"
	@echo "  proto-check    Check if generated proto files are up to date"
	@echo "  proto-clean    Remove generated proto files"
	@echo "  openapi-lint   Lint OpenAPI specifications"
	@echo "  openapi-build  Build OpenAPI HTML documentation"
	@echo "  lint           Run golangci-lint if available"
	@echo "  fmt            Format code and run vet"
	@echo "  imports        Fix import ordering (goimports)"
	@echo "  docker-clean   Stop and remove compose services, images, and volumes"
	@echo "  docker-reset   Alias for docker-clean"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Database migrations:"
	@echo "  migrate-install   Install golang-migrate CLI"
	@echo "  migrate-up        Run all pending migrations"
	@echo "  migrate-down      Rollback the last migration"
	@echo "  migrate-down-all  Rollback all migrations"
	@echo "  migrate-create    Create new migration (name=<name>)"
	@echo "  migrate-status    Show current migration version"
	@echo "  migrate-force     Force set version (v=<version>)"
	@echo "  migrate-validate  Validate migration state is clean"
	@echo ""
	@echo "  help           Show this help"
