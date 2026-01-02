package allowlist

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"credo/internal/ratelimit/models"
	id "credo/pkg/domain"
	"credo/pkg/requestcontext"

	"github.com/google/uuid"
)

// PostgresStore persists allowlist entries in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed allowlist store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Add(ctx context.Context, entry *models.AllowlistEntry) error {
	if entry == nil {
		return fmt.Errorf("allowlist entry is required")
	}
	query := `
		INSERT INTO rate_limit_allowlist (id, entry_type, identifier, reason, expires_at, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (entry_type, identifier) DO UPDATE SET
			reason = EXCLUDED.reason,
			expires_at = EXCLUDED.expires_at,
			created_at = EXCLUDED.created_at,
			created_by = EXCLUDED.created_by
	`
	_, err := s.db.ExecContext(ctx, query,
		entry.ID,
		string(entry.Type),
		entry.Identifier.String(),
		entry.Reason,
		entry.ExpiresAt,
		entry.CreatedAt,
		uuid.UUID(entry.CreatedBy),
	)
	if err != nil {
		return fmt.Errorf("add allowlist entry: %w", err)
	}
	return nil
}

func (s *PostgresStore) Remove(ctx context.Context, entryType models.AllowlistEntryType, identifier string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_allowlist WHERE entry_type = $1 AND identifier = $2`, string(entryType), identifier)
	if err != nil {
		return fmt.Errorf("remove allowlist entry: %w", err)
	}
	return nil
}

func (s *PostgresStore) IsAllowlisted(ctx context.Context, identifier string) (bool, error) {
	if identifier == "" {
		return false, nil
	}
	now := requestcontext.Now(ctx)
	query := `
		SELECT 1
		FROM rate_limit_allowlist
		WHERE identifier = $1
		  AND (expires_at IS NULL OR expires_at > $2)
		LIMIT 1
	`
	var exists int
	if err := s.db.QueryRowContext(ctx, query, identifier, now).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check allowlist: %w", err)
	}
	return true, nil
}

func (s *PostgresStore) List(ctx context.Context) ([]*models.AllowlistEntry, error) {
	now := requestcontext.Now(ctx)
	query := `
		SELECT id, entry_type, identifier, reason, expires_at, created_at, created_by
		FROM rate_limit_allowlist
		WHERE expires_at IS NULL OR expires_at > $1
	`
	rows, err := s.db.QueryContext(ctx, query, now)
	if err != nil {
		return nil, fmt.Errorf("list allowlist entries: %w", err)
	}
	defer rows.Close()

	var entries []*models.AllowlistEntry
	for rows.Next() {
		entry, err := scanAllowlistEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan allowlist entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowlist entries: %w", err)
	}
	return entries, nil
}

// StartCleanup runs periodic cleanup of expired entries until ctx is cancelled.
func (s *PostgresStore) StartCleanup(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_allowlist WHERE expires_at IS NOT NULL AND expires_at <= $1`, time.Now()); err != nil {
				return fmt.Errorf("cleanup allowlist entries: %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type allowlistRow interface {
	Scan(dest ...any) error
}

func scanAllowlistEntry(row allowlistRow) (*models.AllowlistEntry, error) {
	var entry models.AllowlistEntry
	var entryType string
	var expiresAt sql.NullTime
	var createdBy uuid.UUID
	if err := row.Scan(&entry.ID, &entryType, &entry.Identifier, &entry.Reason, &expiresAt, &entry.CreatedAt, &createdBy); err != nil {
		return nil, err
	}
	entry.Type = models.AllowlistEntryType(entryType)
	entry.CreatedBy = id.UserID(createdBy)
	if expiresAt.Valid {
		entry.ExpiresAt = &expiresAt.Time
	}
	return &entry, nil
}
