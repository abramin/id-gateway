package authorizationcode

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/auth/models"
	authsqlc "credo/internal/auth/store/sqlc"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
)

// PostgresStore persists authorization codes in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *authsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed authorization code store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: authsqlc.New(db),
	}
}

func (s *PostgresStore) Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error {
	if authCode == nil {
		return fmt.Errorf("authorization code is required")
	}
	err := s.queries.CreateAuthorizationCode(ctx, authsqlc.CreateAuthorizationCodeParams{
		ID:          authCode.ID,
		Code:        authCode.Code,
		SessionID:   uuid.UUID(authCode.SessionID),
		RedirectUri: authCode.RedirectURI,
		ExpiresAt:   authCode.ExpiresAt,
		Used:        authCode.Used,
		CreatedAt:   authCode.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("create authorization code: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByCode(ctx context.Context, code string) (*models.AuthorizationCodeRecord, error) {
	record, err := s.queries.GetAuthorizationCodeByCode(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("authorization code not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find authorization code: %w", err)
	}
	return toAuthorizationCode(record), nil
}

func (s *PostgresStore) MarkUsed(ctx context.Context, code string) error {
	res, err := s.queries.MarkAuthorizationCodeUsed(ctx, code)
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
	res, err := s.queries.DeleteExpiredAuthorizationCodes(ctx, now)
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

	qtx := s.queries.WithTx(tx)
	row, err := qtx.GetAuthorizationCodeForUpdate(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find authorization code for execute: %w", err)
	}

	record := toAuthorizationCode(row)
	if err := validate(record); err != nil {
		return record, err
	}

	mutate(record)
	if err := qtx.UpdateAuthorizationCodeUsed(ctx, authsqlc.UpdateAuthorizationCodeUsedParams{
		Code: record.Code,
		Used: record.Used,
	}); err != nil {
		return nil, fmt.Errorf("update authorization code: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit authorization code execute: %w", err)
	}
	return record, nil
}

func toAuthorizationCode(record authsqlc.AuthorizationCode) *models.AuthorizationCodeRecord {
	return &models.AuthorizationCodeRecord{
		ID:          record.ID,
		Code:        record.Code,
		SessionID:   id.SessionID(record.SessionID),
		RedirectURI: record.RedirectUri,
		ExpiresAt:   record.ExpiresAt,
		Used:        record.Used,
		CreatedAt:   record.CreatedAt,
	}
}
