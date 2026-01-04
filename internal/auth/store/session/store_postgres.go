package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"credo/internal/auth/models"
	authsqlc "credo/internal/auth/store/sqlc"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
)

// PostgresStore persists sessions in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *authsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed session store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: authsqlc.New(db),
	}
}

func (s *PostgresStore) Create(ctx context.Context, session *models.Session) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	scopeBytes, err := json.Marshal(session.RequestedScope)
	if err != nil {
		return fmt.Errorf("marshal session scopes: %w", err)
	}

	err = s.queries.CreateSession(ctx, authsqlc.CreateSessionParams{
		ID:                    uuid.UUID(session.ID),
		UserID:                uuid.UUID(session.UserID),
		ClientID:              uuid.UUID(session.ClientID),
		TenantID:              uuid.UUID(session.TenantID),
		RequestedScope:        scopeBytes,
		Status:                string(session.Status),
		LastRefreshedAt:       nullTime(session.LastRefreshedAt),
		LastAccessTokenJti:    session.LastAccessTokenJTI,
		DeviceID:              session.DeviceID,
		DeviceFingerprintHash: session.DeviceFingerprintHash,
		DeviceDisplayName:     session.DeviceDisplayName,
		ApproximateLocation:   session.ApproximateLocation,
		CreatedAt:             session.CreatedAt,
		ExpiresAt:             session.ExpiresAt,
		LastSeenAt:            session.LastSeenAt,
		RevokedAt:             nullTime(session.RevokedAt),
	})
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByID(ctx context.Context, sessionID id.SessionID) (*models.Session, error) {
	row, err := s.queries.GetSessionByID(ctx, uuid.UUID(sessionID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find session by id: %w", err)
	}
	session, err := toSession(row)
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	return session, nil
}

func (s *PostgresStore) ListByUser(ctx context.Context, userID id.UserID) ([]*models.Session, error) {
	rows, err := s.queries.ListSessionsByUser(ctx, uuid.UUID(userID))
	if err != nil {
		return nil, fmt.Errorf("list sessions by user: %w", err)
	}

	sessions := make([]*models.Session, 0, len(rows))
	for _, row := range rows {
		session, err := toSession(row)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (s *PostgresStore) UpdateSession(ctx context.Context, session *models.Session) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	return s.updateSession(ctx, s.queries, session)
}

func (s *PostgresStore) DeleteSessionsByUser(ctx context.Context, userID id.UserID) error {
	res, err := s.queries.DeleteSessionsByUser(ctx, uuid.UUID(userID))
	if err != nil {
		return fmt.Errorf("delete sessions by user: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete sessions rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}
	return nil
}

func (s *PostgresStore) RevokeSessionIfActive(ctx context.Context, sessionID id.SessionID, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revoke session tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	row, err := qtx.GetSessionForUpdate(ctx, uuid.UUID(sessionID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sentinel.ErrNotFound
		}
		return fmt.Errorf("find session for revoke: %w", err)
	}

	session, err := toSession(row)
	if err != nil {
		return fmt.Errorf("scan session: %w", err)
	}
	if err := session.CanRevoke(); err != nil {
		return ErrSessionRevoked
	}
	session.ApplyRevocation(now)

	if err := s.updateSession(ctx, qtx, session); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revoke session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions removes all sessions that have expired as of the given time.
func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	res, err := s.queries.DeleteExpiredSessions(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions rows: %w", err)
	}
	return int(rows), nil
}

func (s *PostgresStore) ListAll(ctx context.Context) (map[id.SessionID]*models.Session, error) {
	rows, err := s.queries.ListSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}

	sessions := make(map[id.SessionID]*models.Session, len(rows))
	for _, row := range rows {
		session, err := toSession(row)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions[session.ID] = session
	}
	return sessions, nil
}

// Execute atomically validates and mutates a session under lock.
func (s *PostgresStore) Execute(ctx context.Context, sessionID id.SessionID, validate func(*models.Session) error, mutate func(*models.Session)) (*models.Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin session execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	row, err := qtx.GetSessionForUpdate(ctx, uuid.UUID(sessionID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find session for execute: %w", err)
	}

	session, err := toSession(row)
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	if err := validate(session); err != nil {
		return nil, err
	}

	mutate(session)
	if err := s.updateSession(ctx, qtx, session); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit session execute: %w", err)
	}
	return session, nil
}

func toSession(row authsqlc.Session) (*models.Session, error) {
	var scopes []string
	if len(row.RequestedScope) > 0 {
		if err := json.Unmarshal(row.RequestedScope, &scopes); err != nil {
			return nil, fmt.Errorf("unmarshal session scopes: %w", err)
		}
	}

	session := &models.Session{
		ID:                    id.SessionID(row.ID),
		UserID:                id.UserID(row.UserID),
		ClientID:              id.ClientID(row.ClientID),
		TenantID:              id.TenantID(row.TenantID),
		RequestedScope:        scopes,
		Status:                models.SessionStatus(row.Status),
		LastAccessTokenJTI:    row.LastAccessTokenJti,
		DeviceID:              row.DeviceID,
		DeviceFingerprintHash: row.DeviceFingerprintHash,
		DeviceDisplayName:     row.DeviceDisplayName,
		ApproximateLocation:   row.ApproximateLocation,
		CreatedAt:             row.CreatedAt,
		ExpiresAt:             row.ExpiresAt,
		LastSeenAt:            row.LastSeenAt,
	}
	if row.LastRefreshedAt.Valid {
		session.LastRefreshedAt = &row.LastRefreshedAt.Time
	}
	if row.RevokedAt.Valid {
		session.RevokedAt = &row.RevokedAt.Time
	}
	return session, nil
}

func (s *PostgresStore) updateSession(ctx context.Context, queries *authsqlc.Queries, session *models.Session) error {
	scopeBytes, err := json.Marshal(session.RequestedScope)
	if err != nil {
		return fmt.Errorf("marshal session scopes: %w", err)
	}

	res, err := queries.UpdateSession(ctx, authsqlc.UpdateSessionParams{
		ID:                    uuid.UUID(session.ID),
		UserID:                uuid.UUID(session.UserID),
		ClientID:              uuid.UUID(session.ClientID),
		TenantID:              uuid.UUID(session.TenantID),
		RequestedScope:        scopeBytes,
		Status:                string(session.Status),
		LastRefreshedAt:       nullTime(session.LastRefreshedAt),
		LastAccessTokenJti:    session.LastAccessTokenJTI,
		DeviceID:              session.DeviceID,
		DeviceFingerprintHash: session.DeviceFingerprintHash,
		DeviceDisplayName:     session.DeviceDisplayName,
		ApproximateLocation:   session.ApproximateLocation,
		CreatedAt:             session.CreatedAt,
		ExpiresAt:             session.ExpiresAt,
		LastSeenAt:            session.LastSeenAt,
		RevokedAt:             nullTime(session.RevokedAt),
	})
	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update session rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}
	return nil
}

func nullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
