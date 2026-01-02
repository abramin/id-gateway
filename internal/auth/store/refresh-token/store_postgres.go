package refreshtoken

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

// PostgresStore persists refresh tokens in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed refresh token store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Create(ctx context.Context, token *models.RefreshTokenRecord) error {
	if token == nil {
		return fmt.Errorf("refresh token is required")
	}
	query := `
		INSERT INTO refresh_tokens (id, token, session_id, expires_at, used, last_refreshed_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.db.ExecContext(ctx, query,
		token.ID,
		token.Token,
		uuid.UUID(token.SessionID),
		token.ExpiresAt,
		token.Used,
		nullTime(token.LastRefreshedAt),
		token.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (s *PostgresStore) Find(ctx context.Context, token string) (*models.RefreshTokenRecord, error) {
	query := `
		SELECT id, token, session_id, expires_at, used, last_refreshed_at, created_at
		FROM refresh_tokens
		WHERE token = $1
	`
	record, err := scanRefreshToken(s.db.QueryRowContext(ctx, query, token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) FindBySessionID(ctx context.Context, sessionID id.SessionID, now time.Time) (*models.RefreshTokenRecord, error) {
	query := `
		SELECT id, token, session_id, expires_at, used, last_refreshed_at, created_at
		FROM refresh_tokens
		WHERE session_id = $1 AND used = FALSE AND expires_at > $2
		ORDER BY created_at DESC
		LIMIT 1
	`
	record, err := scanRefreshToken(s.db.QueryRowContext(ctx, query, uuid.UUID(sessionID), now))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("refresh token not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find refresh token by session: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) DeleteBySessionID(ctx context.Context, sessionID id.SessionID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE session_id = $1`, uuid.UUID(sessionID))
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE used = TRUE`)
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
		_ = tx.Rollback()
	}()

	query := `
		SELECT id, token, session_id, expires_at, used, last_refreshed_at, created_at
		FROM refresh_tokens
		WHERE token = $1
		FOR UPDATE
	`
	record, err := scanRefreshToken(tx.QueryRowContext(ctx, query, token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find refresh token for execute: %w", err)
	}

	if err := validate(record); err != nil {
		return record, err
	}

	mutate(record)
	_, err = tx.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET used = $2, last_refreshed_at = $3
		WHERE token = $1
	`, record.Token, record.Used, nullTime(record.LastRefreshedAt))
	if err != nil {
		return nil, fmt.Errorf("update refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit refresh token execute: %w", err)
	}
	return record, nil
}

type refreshTokenRow interface {
	Scan(dest ...any) error
}

func scanRefreshToken(row refreshTokenRow) (*models.RefreshTokenRecord, error) {
	var record models.RefreshTokenRecord
	var sessionID uuid.UUID
	var lastRefreshed sql.NullTime
	if err := row.Scan(&record.ID, &record.Token, &sessionID, &record.ExpiresAt, &record.Used, &lastRefreshed, &record.CreatedAt); err != nil {
		return nil, err
	}
	record.SessionID = id.SessionID(sessionID)
	if lastRefreshed.Valid {
		record.LastRefreshedAt = &lastRefreshed.Time
	}
	return &record, nil
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
