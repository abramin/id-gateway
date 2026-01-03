//go:build integration

package containers

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"credo/migrations"
	id "credo/pkg/domain"
)

// PostgresContainer wraps a testcontainers Postgres instance.
type PostgresContainer struct {
	Container testcontainers.Container
	DSN       string
	DB        *sql.DB
}

// NewPostgresContainer starts a new Postgres container with migrations applied.
func NewPostgresContainer(t *testing.T) *PostgresContainer {
	t.Helper()

	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("credo_test"),
		postgres.WithUsername("credo"),
		postgres.WithPassword("credo_test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to get postgres connection string: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("failed to connect to postgres: %v", err)
	}

	pc := &PostgresContainer{
		Container: container,
		DSN:       dsn,
		DB:        db,
	}

	if err := pc.runMigrations(ctx); err != nil {
		_ = db.Close()
		_ = container.Terminate(ctx)
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Note: We don't register t.Cleanup here because the container is managed
	// by the singleton Manager and shared across test suites. Ryuk (testcontainers'
	// cleanup sidecar) handles container cleanup when the test process exits.

	return pc
}

// runMigrations executes all *.up.sql migrations from the embedded migrations.FS.
func (p *PostgresContainer) runMigrations(ctx context.Context) error {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, file := range files {
		content, err := fs.ReadFile(migrations.FS, file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}

		if _, err := p.DB.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("execute migration %s: %w", file, err)
		}
	}

	return nil
}

// TruncateTables clears all data from the specified tables.
// Use between tests to ensure isolation without restarting the container.
func (p *PostgresContainer) TruncateTables(ctx context.Context, tables ...string) error {
	for _, table := range tables {
		_, err := p.DB.ExecContext(ctx, "TRUNCATE TABLE "+table+" CASCADE")
		if err != nil {
			return fmt.Errorf("truncate %s: %w", table, err)
		}
	}
	return nil
}

// TruncateAll truncates the standard integration test tables.
func (p *PostgresContainer) TruncateAll(ctx context.Context) error {
	return p.TruncateTables(ctx, "outbox", "audit_events")
}

// TruncateModuleTables truncates all module tables for full integration test isolation.
// Tables are truncated with CASCADE to handle foreign key dependencies.
func (p *PostgresContainer) TruncateModuleTables(ctx context.Context) error {
	// Order matters due to FK constraints; CASCADE handles dependencies
	tables := []string{
		// Audit tables (no FK dependencies on them)
		"outbox",
		"audit_events",

		// Rate limit tables
		"global_throttle",
		"auth_lockouts",
		"rate_limit_events",
		"rate_limit_allowlist",

		// Evidence tables (vc_credentials depends on users)
		"vc_credentials",
		"citizen_cache",
		"sanctions_cache",
		"token_revocations",

		// Auth tables (sessions, codes, tokens depend on users/clients)
		"refresh_tokens",
		"authorization_codes",
		"sessions",
		"consents",

		// Core tables (users depends on tenants via clients)
		"users",
		"clients",
		"tenants",
	}
	return p.TruncateTables(ctx, tables...)
}

// Exec runs a SQL statement and returns the result.
func (p *PostgresContainer) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return p.DB.ExecContext(ctx, query, args...)
}

// Query runs a SQL query and returns rows.
func (p *PostgresContainer) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.DB.QueryContext(ctx, query, args...)
}

// QueryRow runs a SQL query expected to return a single row.
func (p *PostgresContainer) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return p.DB.QueryRowContext(ctx, query, args...)
}

// CreateTestTenant inserts a test tenant and returns its ID.
// Fails the test if insertion fails.
func (p *PostgresContainer) CreateTestTenant(ctx context.Context, t testing.TB) id.TenantID {
	t.Helper()
	tenantID := id.TenantID(uuid.New())
	_, err := p.Exec(ctx, `
		INSERT INTO tenants (id, name, status, created_at, updated_at)
		VALUES ($1, $2, 'active', NOW(), NOW())
	`, uuid.UUID(tenantID), "Test Tenant "+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateTestTenant: %v", err)
	}
	return tenantID
}

// CreateTestUser inserts a test user for the given tenant and returns its ID.
// Fails the test if insertion fails.
func (p *PostgresContainer) CreateTestUser(ctx context.Context, t testing.TB, tenantID id.TenantID) id.UserID {
	t.Helper()
	userID := id.UserID(uuid.New())
	_, err := p.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, 'Test', 'User', true, 'active')
	`, uuid.UUID(userID), uuid.UUID(tenantID), "test-"+uuid.NewString()+"@example.com")
	if err != nil {
		t.Fatalf("CreateTestUser: %v", err)
	}
	return userID
}

// CreateTestClient inserts a test OAuth client for the given tenant and returns its ID.
// Fails the test if insertion fails.
func (p *PostgresContainer) CreateTestClient(ctx context.Context, t testing.TB, tenantID id.TenantID) id.ClientID {
	t.Helper()
	clientID := id.ClientID(uuid.New())
	_, err := p.Exec(ctx, `
		INSERT INTO clients (id, tenant_id, name, oauth_client_id, redirect_uris, allowed_grants, allowed_scopes, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', NOW(), NOW())
	`, uuid.UUID(clientID), uuid.UUID(tenantID), "Test Client", uuid.NewString(),
		`["https://example.com/callback"]`, `["authorization_code"]`, `["openid"]`)
	if err != nil {
		t.Fatalf("CreateTestClient: %v", err)
	}
	return clientID
}
