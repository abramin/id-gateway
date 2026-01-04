package refreshtoken

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

// PostgresStore persists refresh tokens in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *authsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed refresh token store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: authsqlc.New(db),
	}
}

func (s *PostgresStore) Create(ctx context.Context, token *models.RefreshTokenRecord) error {
	if token == nil {
		return fmt.Errorf("refresh token is required")
	}
	err := s.queries.CreateRefreshToken(ctx, authsqlc.CreateRefreshTokenParams{
		ID:              token.ID,
		Token:           token.Token,
		SessionID:       uuid.UUID(token.SessionID),
		ExpiresAt:       token.ExpiresAt,
		Used:            token.Used,
		LastRefreshedAt: nullTime(token.LastRefreshedAt),
		CreatedAt:       token.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (s *PostgresStore) Find(ctx context.Context, token string) (*models.RefreshTokenRecord, error) {
	record, err := s.queries.GetRefreshTokenByToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return toRefreshToken(record), nil
}

func (s *PostgresStore) FindBySessionID(ctx context.Context, sessionID id.SessionID, now time.Time) (*models.RefreshTokenRecord, error) {
	record, err := s.queries.GetRefreshTokenBySession(ctx, authsqlc.GetRefreshTokenBySessionParams{
		SessionID: uuid.UUID(sessionID),
		ExpiresAt: now,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find refresh token by session: %w", err)
	}
	return toRefreshToken(record), nil
}

func (s *PostgresStore) DeleteBySessionID(ctx context.Context, sessionID id.SessionID) error {
	res, err := s.queries.DeleteRefreshTokensBySession(ctx, uuid.UUID(sessionID))
	if err != nil {
		return fmt.Errorf("delete refresh tokens by session: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete refresh tokens rows: %w", err)
	}
	if rows == 0 {
		return sentinel.ErrNotFound
	}
	return nil
}

// DeleteExpiredTokens removes all refresh tokens that have expired as of the given time.
func (s *PostgresStore) DeleteExpiredTokens(ctx context.Context, now time.Time) (int, error) {
	res, err := s.queries.DeleteExpiredRefreshTokens(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens rows: %w", err)
	}
	return int(rows), nil
}

func (s *PostgresStore) DeleteUsedTokens(ctx context.Context) (int, error) {
	res, err := s.queries.DeleteUsedRefreshTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete used refresh tokens: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete used refresh tokens rows: %w", err)
	}
	return int(rows), nil
}

// Execute atomically validates and mutates a refresh token under lock.
func (s *PostgresStore) Execute(ctx context.Context, token string, validate func(*models.RefreshTokenRecord) error, mutate func(*models.RefreshTokenRecord)) (*models.RefreshTokenRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin refresh token execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	row, err := qtx.GetRefreshTokenForUpdate(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find refresh token for execute: %w", err)
	}

	record := toRefreshToken(row)
	if err := validate(record); err != nil {
		return record, err
	}

	mutate(record)
	if err := qtx.UpdateRefreshTokenUsage(ctx, authsqlc.UpdateRefreshTokenUsageParams{
		Token:           record.Token,
		Used:            record.Used,
		LastRefreshedAt: nullTime(record.LastRefreshedAt),
	}); err != nil {
		return nil, fmt.Errorf("update refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit refresh token execute: %w", err)
	}
	return record, nil
}

func toRefreshToken(record authsqlc.RefreshToken) *models.RefreshTokenRecord {
	token := &models.RefreshTokenRecord{
		ID:        record.ID,
		Token:     record.Token,
		SessionID: id.SessionID(record.SessionID),
		ExpiresAt: record.ExpiresAt,
		Used:      record.Used,
		CreatedAt: record.CreatedAt,
	}
	if record.LastRefreshedAt.Valid {
		token.LastRefreshedAt = &record.LastRefreshedAt.Time
	}
	return token
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
