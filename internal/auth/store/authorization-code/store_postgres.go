package authorizationcode

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
)

// PostgresStore persists authorization codes in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed authorization code store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error {
	if authCode == nil {
		return fmt.Errorf("authorization code is required")
	}
	query := `
		INSERT INTO authorization_codes (id, code, session_id, redirect_uri, expires_at, used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.ExecContext(ctx, query,
		authCode.ID,
		authCode.Code,
		uuid.UUID(authCode.SessionID),
		authCode.RedirectURI,
		authCode.ExpiresAt,
		authCode.Used,
		authCode.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create authorization code: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error) {
	query := `
		SELECT id, code, session_id, redirect_uri, expires_at, used, created_at
		FROM authorization_codes
		WHERE code = $1
	`
	record, err := scanAuthorizationCode(s.db.QueryRowContext(ctx, query, code))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find authorization code: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) MarkUsed(ctx context.Context, code string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE authorization_codes SET used = TRUE WHERE code = $1`, code)
	if err != nil {
		return fmt.Errorf("mark authorization code used: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mark authorization code used rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
	}
	return nil
}

// DeleteExpiredCodes removes all authorization codes that have expired as of the given time.
func (s *PostgresStore) DeleteExpiredCodes(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM authorization_codes WHERE expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired authorization codes: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired authorization codes rows: %w", err)
	}
	return int(rows), nil
}

// Execute atomically validates and mutates an auth code under lock.
func (s *PostgresStore) Execute(ctx context.Context, code string, validate func(*models.AuthorizationCodeRecord) error, mutate func(*models.AuthorizationCodeRecord)) (*models.AuthorizationCodeRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin authorization code execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := `
		SELECT id, code, session_id, redirect_uri, expires_at, used, created_at
		FROM authorization_codes
		WHERE code = $1
		FOR UPDATE
	`
	record, err := scanAuthorizationCode(tx.QueryRowContext(ctx, query, code))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find authorization code for execute: %w", err)
	}

	if err := validate(record); err != nil {
		return record, err
	}

	mutate(record)
	if _, err := tx.ExecContext(ctx, `UPDATE authorization_codes SET used = $2 WHERE code = $1`, record.Code, record.Used); err != nil {
		return nil, fmt.Errorf("update authorization code: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit authorization code execute: %w", err)
	}
	return record, nil
}

type authCodeRow interface {
	Scan(dest ...any) error
}

func scanAuthorizationCode(row authCodeRow) (*models.AuthorizationCodeRecord, error) {
	var record models.AuthorizationCodeRecord
	var sessionID uuid.UUID
	if err := row.Scan(&record.ID, &record.Code, &sessionID, &record.RedirectURI, &record.ExpiresAt, &record.Used, &record.CreatedAt); err != nil {
		return nil, err
	}
	record.SessionID = id.SessionID(sessionID)
	return &record, nil
}
