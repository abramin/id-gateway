package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"credo/internal/consent/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"

	"github.com/google/uuid"
)

// PostgresStore persists consent records in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed consent store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Save(ctx context.Context, consent *models.Record) error {
	if consent == nil {
		return fmt.Errorf("consent record is required")
	}
	query := `
		INSERT INTO consents (id, user_id, purpose, granted_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, purpose) DO UPDATE SET
			id = EXCLUDED.id,
			granted_at = EXCLUDED.granted_at,
			expires_at = EXCLUDED.expires_at,
			revoked_at = EXCLUDED.revoked_at
	`
	_, err := s.db.ExecContext(ctx, query,
		uuid.UUID(consent.ID),
		uuid.UUID(consent.UserID),
		string(consent.Purpose),
		consent.GrantedAt,
		consent.ExpiresAt,
		consent.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("save consent: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByUserAndPurpose(ctx context.Context, userID id.UserID, purpose models.Purpose) (*models.Record, error) {
	query := `
		SELECT id, user_id, purpose, granted_at, expires_at, revoked_at
		FROM consents
		WHERE user_id = $1 AND purpose = $2
	`
	record, err := scanConsent(s.db.QueryRowContext(ctx, query, uuid.UUID(userID), string(purpose)))
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
	rows, err := s.db.QueryContext(ctx, query, uuid.UUID(userID))
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	defer rows.Close()

	var records []*models.Record
	now := requestcontext.Now(ctx)
	for rows.Next() {
		record, err := scanConsent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan consent: %w", err)
		}

		if filter != nil {
			if filter.Purpose != nil && record.Purpose != *filter.Purpose {
				continue
			}
			if filter.Status != nil {
				status := record.ComputeStatus(now)
				if status != *filter.Status {
					continue
				}
			}
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
	query := `
		UPDATE consents
		SET granted_at = $2, expires_at = $3, revoked_at = $4
		WHERE id = $1 AND user_id = $5 AND purpose = $6
	`
	res, err := s.db.ExecContext(ctx, query,
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

func (s *PostgresStore) RevokeByUserAndPurpose(ctx context.Context, userID id.UserID, purpose models.Purpose, revokedAt time.Time) (*models.Record, error) {
	query := `
		UPDATE consents
		SET revoked_at = $3
		WHERE user_id = $1 AND purpose = $2 AND revoked_at IS NULL
		RETURNING id, user_id, purpose, granted_at, expires_at, revoked_at
	`
	record, err := scanConsent(s.db.QueryRowContext(ctx, query, uuid.UUID(userID), string(purpose), revokedAt))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("revoke consent: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) DeleteByUser(ctx context.Context, userID id.UserID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM consents WHERE user_id = $1`, uuid.UUID(userID))
	if err != nil {
		return fmt.Errorf("delete consents by user: %w", err)
	}
	return nil
}

// RevokeAllByUser revokes all active consents for a user.
func (s *PostgresStore) RevokeAllByUser(ctx context.Context, userID id.UserID, revokedAt time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE consents SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, uuid.UUID(userID), revokedAt)
	if err != nil {
		return 0, fmt.Errorf("revoke all consents: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke all consents rows: %w", err)
	}
	return int(rows), nil
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
