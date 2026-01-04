package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/consent/models"
	consentsqlc "credo/internal/consent/store/sqlc"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
)

// PostgresStore persists consent records in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	tx      *sql.Tx
	queries *consentsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed consent store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: consentsqlc.New(db),
	}
}

// NewPostgresTx constructs a PostgreSQL-backed consent store bound to a transaction.
func NewPostgresTx(tx *sql.Tx) *PostgresStore {
	return &PostgresStore{
		tx:      tx,
		queries: consentsqlc.New(tx),
	}
}

func (s *PostgresStore) Save(ctx context.Context, consent *models.Record) error {
	if consent == nil {
		return fmt.Errorf("consent record is required")
	}
	storedID, err := s.queries.InsertConsent(ctx, consentsqlc.InsertConsentParams{
		ID:        uuid.UUID(consent.ID),
		UserID:    uuid.UUID(consent.UserID),
		Purpose:   string(consent.Purpose),
		GrantedAt: consent.GrantedAt,
		ExpiresAt: nullTime(consent.ExpiresAt),
		RevokedAt: nullTime(consent.RevokedAt),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sentinel.ErrConflict
		}
		return fmt.Errorf("save consent: %w", err)
	}
	consent.ID = id.ConsentID(storedID)
	return nil
}

func (s *PostgresStore) FindByScope(ctx context.Context, scope models.ConsentScope) (*models.Record, error) {
	record, err := s.queries.GetConsentByScope(ctx, consentsqlc.GetConsentByScopeParams{
		UserID:  uuid.UUID(scope.UserID),
		Purpose: string(scope.Purpose),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find consent: %w", err)
	}
	return toConsent(record), nil
}

func (s *PostgresStore) ListByUser(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error) {
	var (
		rows []consentsqlc.Consent
		err  error
	)
	if filter != nil && filter.Purpose != nil {
		rows, err = s.queries.ListConsentsByUserAndPurpose(ctx, consentsqlc.ListConsentsByUserAndPurposeParams{
			UserID:  uuid.UUID(userID),
			Purpose: string(*filter.Purpose),
		})
	} else {
		rows, err = s.queries.ListConsentsByUser(ctx, uuid.UUID(userID))
	}
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}

	records := make([]*models.Record, 0, len(rows))
	for _, row := range rows {
		records = append(records, toConsent(row))
	}
	return records, nil
}

func (s *PostgresStore) Update(ctx context.Context, consent *models.Record) error {
	if consent == nil {
		return fmt.Errorf("consent record is required")
	}
	return updateConsent(ctx, s.queries, consent)
}

func (s *PostgresStore) RevokeAllByUser(ctx context.Context, userID id.UserID, now time.Time) (int, error) {
	res, err := s.queries.RevokeAllConsentsByUser(ctx, consentsqlc.RevokeAllConsentsByUserParams{
		UserID:    uuid.UUID(userID),
		RevokedAt: sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		return 0, fmt.Errorf("revoke all consents: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke all consents rows: %w", err)
	}
	return int(rows), nil
}

// Execute atomically validates and mutates a consent record under lock.
func (s *PostgresStore) Execute(ctx context.Context, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record) bool) (*models.Record, error) {
	if s.tx != nil {
		return s.executeWithTx(ctx, s.tx, scope, validate, mutate)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin consent execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	record, err := s.executeWithTx(ctx, tx, scope, validate, mutate)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit consent execute: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) executeWithTx(ctx context.Context, tx *sql.Tx, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record) bool) (*models.Record, error) {
	qtx := s.queries.WithTx(tx)
	record, err := qtx.GetConsentByScopeForUpdate(ctx, consentsqlc.GetConsentByScopeForUpdateParams{
		UserID:  uuid.UUID(scope.UserID),
		Purpose: string(scope.Purpose),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find consent for execute: %w", err)
	}

	modelRecord := toConsent(record)
	if err := validate(modelRecord); err != nil {
		return nil, err
	}

	changed := mutate(modelRecord)
	if !changed {
		return modelRecord, nil
	}
	if err := updateConsent(ctx, qtx, modelRecord); err != nil {
		return nil, err
	}
	return modelRecord, nil
}

func (s *PostgresStore) DeleteByUser(ctx context.Context, userID id.UserID) error {
	if err := s.queries.DeleteConsentsByUser(ctx, uuid.UUID(userID)); err != nil {
		return fmt.Errorf("delete consents by user: %w", err)
	}
	return nil
}

func updateConsent(ctx context.Context, queries *consentsqlc.Queries, consent *models.Record) error {
	res, err := queries.UpdateConsent(ctx, consentsqlc.UpdateConsentParams{
		ID:        uuid.UUID(consent.ID),
		GrantedAt: consent.GrantedAt,
		ExpiresAt: nullTime(consent.ExpiresAt),
		RevokedAt: nullTime(consent.RevokedAt),
		UserID:    uuid.UUID(consent.UserID),
		Purpose:   string(consent.Purpose),
	})
	if err != nil {
		return fmt.Errorf("update consent: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update consent rows: %w", err)
	}
	if rows == 0 {
		return sentinel.ErrNotFound
	}
	return nil
}

func toConsent(record consentsqlc.Consent) *models.Record {
	modelRecord := &models.Record{
		ID:        id.ConsentID(record.ID),
		UserID:    id.UserID(record.UserID),
		Purpose:   models.Purpose(record.Purpose),
		GrantedAt: record.GrantedAt,
	}
	if record.ExpiresAt.Valid {
		modelRecord.ExpiresAt = &record.ExpiresAt.Time
	}
	if record.RevokedAt.Valid {
		modelRecord.RevokedAt = &record.RevokedAt.Time
	}
	return modelRecord
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
