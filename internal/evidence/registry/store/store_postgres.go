package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/evidence/registry/metrics"
	"credo/internal/evidence/registry/models"
	id "credo/pkg/domain"
	"credo/pkg/requestcontext"
)

// PostgresCache persists registry cache entries in PostgreSQL.
type PostgresCache struct {
	db       *sql.DB
	cacheTTL time.Duration
	metrics  *metrics.Metrics
}

// NewPostgresCache constructs a PostgreSQL-backed registry cache.
func NewPostgresCache(db *sql.DB, cacheTTL time.Duration, metrics *metrics.Metrics) *PostgresCache {
	return &PostgresCache{
		db:       db,
		cacheTTL: cacheTTL,
		metrics:  metrics,
	}
}

func (c *PostgresCache) FindCitizen(ctx context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error) {
	start := time.Now()
	cutoff := requestcontext.Now(ctx).Add(-c.cacheTTL)
	query := `
		SELECT national_id, full_name, date_of_birth, address, valid, source, checked_at, regulated
		FROM citizen_cache
		WHERE national_id = $1 AND regulated = $2 AND checked_at >= $3
	`
	record, err := scanCitizen(c.db.QueryRowContext(ctx, query, nationalID.String(), regulated, cutoff))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.recordMiss("citizen", start)
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find citizen cache: %w", err)
	}
	c.recordHit("citizen", start)
	return record, nil
}

func (c *PostgresCache) SaveCitizen(ctx context.Context, key id.NationalID, record *models.CitizenRecord, regulated bool) error {
	if record == nil {
		return fmt.Errorf("citizen record is required")
	}
	query := `
		INSERT INTO citizen_cache (
			national_id, full_name, date_of_birth, address, valid, source, checked_at, regulated
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (national_id, regulated) DO UPDATE SET
			full_name = EXCLUDED.full_name,
			date_of_birth = EXCLUDED.date_of_birth,
			address = EXCLUDED.address,
			valid = EXCLUDED.valid,
			source = EXCLUDED.source,
			checked_at = EXCLUDED.checked_at
	`
	_, err := c.db.ExecContext(ctx, query,
		key.String(),
		record.FullName,
		record.DateOfBirth,
		record.Address,
		record.Valid,
		record.Source,
		record.CheckedAt,
		regulated,
	)
	if err != nil {
		return fmt.Errorf("save citizen cache: %w", err)
	}
	return nil
}

func (c *PostgresCache) FindSanction(ctx context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	start := time.Now()
	cutoff := requestcontext.Now(ctx).Add(-c.cacheTTL)
	query := `
		SELECT national_id, listed, source, checked_at
		FROM sanctions_cache
		WHERE national_id = $1 AND checked_at >= $2
	`
	record, err := scanSanction(c.db.QueryRowContext(ctx, query, nationalID.String(), cutoff))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.recordMiss("sanctions", start)
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find sanctions cache: %w", err)
	}
	c.recordHit("sanctions", start)
	return record, nil
}

func (c *PostgresCache) SaveSanction(ctx context.Context, key id.NationalID, record *models.SanctionsRecord) error {
	if record == nil {
		return fmt.Errorf("sanctions record is required")
	}
	query := `
		INSERT INTO sanctions_cache (national_id, listed, source, checked_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (national_id) DO UPDATE SET
			listed = EXCLUDED.listed,
			source = EXCLUDED.source,
			checked_at = EXCLUDED.checked_at
	`
	_, err := c.db.ExecContext(ctx, query,
		key.String(),
		record.Listed,
		record.Source,
		record.CheckedAt,
	)
	if err != nil {
		return fmt.Errorf("save sanctions cache: %w", err)
	}
	return nil
}

type citizenRow interface {
	Scan(dest ...any) error
}

func scanCitizen(row citizenRow) (*models.CitizenRecord, error) {
	var record models.CitizenRecord
	var storedRegulated bool
	if err := row.Scan(&record.NationalID, &record.FullName, &record.DateOfBirth, &record.Address, &record.Valid, &record.Source, &record.CheckedAt, &storedRegulated); err != nil {
		return nil, err
	}
	_ = storedRegulated
	return &record, nil
}

type sanctionRow interface {
	Scan(dest ...any) error
}

func scanSanction(row sanctionRow) (*models.SanctionsRecord, error) {
	var record models.SanctionsRecord
	if err := row.Scan(&record.NationalID, &record.Listed, &record.Source, &record.CheckedAt); err != nil {
		return nil, err
	}
	return &record, nil
}

func (c *PostgresCache) recordHit(recordType string, start time.Time) {
	if c.metrics == nil {
		return
	}
	c.metrics.RecordCacheHit(recordType)
	c.metrics.ObserveLookupDuration(recordType, time.Since(start).Seconds())
}

func (c *PostgresCache) recordMiss(recordType string, start time.Time) {
	if c.metrics == nil {
		return
	}
	c.metrics.RecordCacheMiss(recordType)
	c.metrics.ObserveLookupDuration(recordType, time.Since(start).Seconds())
}
