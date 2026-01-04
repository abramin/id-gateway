package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Config holds database connection configuration.
type Config struct {
	URL             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DefaultConfig returns sensible defaults for database configuration.
func DefaultConfig() Config {
	return Config{
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	}
}

// Pool wraps a *sql.DB with health checking capabilities.
type Pool struct {
	db  *sql.DB
	cfg Config
}

// New creates a new database connection pool.
// Returns nil if the URL is empty.
func New(cfg Config) (*Pool, error) {
	if cfg.URL == "" {
		return nil, nil
	}

	db, err := sql.Open("pgx", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close() //nolint:errcheck // best-effort cleanup on init failure
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Pool{db: db, cfg: cfg}, nil
}

// DB returns the underlying *sql.DB for query operations.
func (p *Pool) DB() *sql.DB {
	return p.db
}

// Health checks if the database is reachable.
func (p *Pool) Health(ctx context.Context) error {
	if p == nil || p.db == nil {
		return fmt.Errorf("database not configured")
	}
	return p.db.PingContext(ctx)
}

// Close closes the database connection pool.
func (p *Pool) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

// Stats returns database connection pool statistics.
func (p *Pool) Stats() sql.DBStats {
	if p == nil || p.db == nil {
		return sql.DBStats{}
	}
	return p.db.Stats()
}
