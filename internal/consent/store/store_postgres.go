package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"credo/internal/consent/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
)

// PostgresStore persists consent records in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
	tx *sql.Tx
}

// NewPostgres constructs a PostgreSQL-backed consent store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// NewPostgresTx constructs a PostgreSQL-backed consent store bound to a transaction.
func NewPostgresTx(tx *sql.Tx) *PostgresStore {
	return &PostgresStore{tx: tx}
}

type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *PostgresStore) execer() dbExecutor {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

func (s *PostgresStore) Save(ctx context.Context, consent *models.Record) error {
	if consent == nil {
		return fmt.Errorf("consent record is required")
	}
	query := `
		INSERT INTO consents (id, user_id, purpose, granted_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, purpose) DO NOTHING
		RETURNING id
	`
	var storedID uuid.UUID
	err := s.execer().QueryRowContext(ctx, query,
		uuid.UUID(consent.ID),
		uuid.UUID(consent.UserID),
		string(consent.Purpose),
		consent.GrantedAt,
		consent.ExpiresAt,
		consent.RevokedAt,
	).Scan(&storedID)
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
	query := `
		SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
		FROM consents
		WHERE user_id = $1 AND purpose = $2
	`
	record, err := scanConsent(s.execer().QueryRowContext(ctx, query, uuid.UUID(scope.UserID), string(scope.Purpose)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find consent: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) ListByUser(ctx context.Context, userID id.UserID, filter *models.RecordFilter) ([]*models.Record, error) {
	query := `
		SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
		FROM consents
		WHERE user_id = $1
	`
	args := []any{uuid.UUID(userID)}
	if filter != nil && filter.Purpose != nil {
		query += " AND purpose = $2"
		args = append(args, string(*filter.Purpose))
	}

	rows, err := s.execer().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	defer rows.Close()

	var records []*models.Record
	for rows.Next() {
		record, err := scanConsent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan consent: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate consents: %w", err)
	}
	return records, nil
}

func (s *PostgresStore) Update(ctx context.Context, consent *models.Record) error {
	if consent == nil {
		return fmt.Errorf("consent record is required")
	}
	return updateConsent(ctx, s.execer(), consent)
}

// Execute atomically validates and mutates a consent record under lock.
func (s *PostgresStore) Execute(ctx context.Context, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record)) (*models.Record, error) {
	if s.tx != nil {
		return s.executeWithTx(ctx, s.tx, scope, validate, mutate)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin consent execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
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

func (s *PostgresStore) executeWithTx(ctx context.Context, tx *sql.Tx, scope models.ConsentScope, validate func(*models.Record) error, mutate func(*models.Record)) (*models.Record, error) {
	query := `
		SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
		FROM consents
		WHERE user_id = $1 AND purpose = $2
		FOR UPDATE
	`
	record, err := scanConsent(tx.QueryRowContext(ctx, query, uuid.UUID(scope.UserID), string(scope.Purpose)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find consent for execute: %w", err)
	}

	if err := validate(record); err != nil {
		return nil, err
	}

	mutate(record)
	if err := updateConsent(ctx, tx, record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *PostgresStore) DeleteByUser(ctx context.Context, userID id.UserID) error {
	_, err := s.execer().ExecContext(ctx, `DELETE FROM consents WHERE user_id = $1`, uuid.UUID(userID))
	if err != nil {
		return fmt.Errorf("delete consents by user: %w", err)
	}
	return nil
}

func updateConsent(ctx context.Context, exec dbExecutor, consent *models.Record) error {
	query := `
		UPDATE consents
		SET granted_at = $2, expires_at = $3, revoked_at = $4
		WHERE id = $1 AND user_id = $5 AND purpose = $6
	`
	res, err := exec.ExecContext(ctx, query,
		uuid.UUID(consent.ID),
		consent.GrantedAt,
		consent.ExpiresAt,
		consent.RevokedAt,
		uuid.UUID(consent.UserID),
		string(consent.Purpose),
	)
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

type consentRow interface {
	Scan(dest ...any) error
}

func scanConsent(row consentRow) (*models.Record, error) {
	var record models.Record
	var userID uuid.UUID
	var purpose string
	var expiresAt sql.NullTime
	var revokedAt sql.NullTime
	if err := row.Scan(&record.ID, &userID, &purpose, &record.GrantedAt, &expiresAt, &revokedAt); err != nil {
		return nil, err
	}
	record.UserID = id.UserID(userID)
	record.Purpose = models.Purpose(purpose)
	if expiresAt.Valid {
		record.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		record.RevokedAt = &revokedAt.Time
	}
	return &record, nil
}
