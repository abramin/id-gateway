//go:build integration

package containers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
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

	t.Cleanup(func() {
		_ = db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = container.Terminate(ctx)
	})

	return pc
}

// runMigrations executes all *.up.sql migrations from the migrations directory.
func (p *PostgresContainer) runMigrations(ctx context.Context) error {
	migrationsDir := findMigrationsDir()

	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		return fmt.Errorf("glob migrations: %w", err)
	}

	sort.Strings(files)

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}

		if _, err := p.DB.ExecContext(ctx, string(content)); err != nil {
			return fmt.Errorf("execute migration %s: %w", file, err)
		}
	}

	return nil
}

// findMigrationsDir locates the migrations directory relative to the source file.
func findMigrationsDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "migrations"
	}

	// Navigate from pkg/testkit/containers/ to project root
	dir := filepath.Dir(filename)
	for i := 0; i < 4; i++ {
		dir = filepath.Dir(dir)
	}

	return filepath.Join(dir, "migrations")
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
