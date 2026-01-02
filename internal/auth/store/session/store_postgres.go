package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
)

// PostgresStore persists sessions in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed session store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Create(ctx context.Context, session *models.Session) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	scopeBytes, err := json.Marshal(session.RequestedScope)
	if err != nil {
		return fmt.Errorf("marshal session scopes: %w", err)
	}

	query := `
		INSERT INTO sessions (
			id, user_id, client_id, tenant_id, requested_scope, status,
			last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
			device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	_, err = s.db.ExecContext(ctx, query,
		uuid.UUID(session.ID),
		uuid.UUID(session.UserID),
		uuid.UUID(session.ClientID),
		uuid.UUID(session.TenantID),
		scopeBytes,
		string(session.Status),
		nullTime(session.LastRefreshedAt),
		session.LastAccessTokenJTI,
		session.DeviceID,
		session.DeviceFingerprintHash,
		session.DeviceDisplayName,
		session.ApproximateLocation,
		session.CreatedAt,
		session.ExpiresAt,
		session.LastSeenAt,
		nullTime(session.RevokedAt),
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByID(ctx context.Context, sessionID id.SessionID) (*models.Session, error) {
	query := `
		SELECT id, user_id, client_id, tenant_id, requested_scope, status,
			last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
			device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions
		WHERE id = $1
	`
	session, err := scanSession(s.db.QueryRowContext(ctx, query, uuid.UUID(sessionID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find session by id: %w", err)
	}
	return session, nil
}

func (s *PostgresStore) ListByUser(ctx context.Context, userID id.UserID) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, client_id, tenant_id, requested_scope, status,
			last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
			device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions
		WHERE user_id = $1
	`
	rows, err := s.db.QueryContext(ctx, query, uuid.UUID(userID))
	if err != nil {
		return nil, fmt.Errorf("list sessions by user: %w", err)
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return sessions, nil
}

func (s *PostgresStore) UpdateSession(ctx context.Context, session *models.Session) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	scopeBytes, err := json.Marshal(session.RequestedScope)
	if err != nil {
		return fmt.Errorf("marshal session scopes: %w", err)
	}

	query := `
		UPDATE sessions
		SET user_id = $2,
			client_id = $3,
			tenant_id = $4,
			requested_scope = $5,
			status = $6,
			last_refreshed_at = $7,
			last_access_token_jti = $8,
			device_id = $9,
			device_fingerprint_hash = $10,
			device_display_name = $11,
			approximate_location = $12,
			created_at = $13,
			expires_at = $14,
			last_seen_at = $15,
			revoked_at = $16
		WHERE id = $1
	`

	res, err := s.db.ExecContext(ctx, query,
		uuid.UUID(session.ID),
		uuid.UUID(session.UserID),
		uuid.UUID(session.ClientID),
		uuid.UUID(session.TenantID),
		scopeBytes,
		string(session.Status),
		nullTime(session.LastRefreshedAt),
		session.LastAccessTokenJTI,
		session.DeviceID,
		session.DeviceFingerprintHash,
		session.DeviceDisplayName,
		session.ApproximateLocation,
		session.CreatedAt,
		session.ExpiresAt,
		session.LastSeenAt,
		nullTime(session.RevokedAt),
	)
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

func (s *PostgresStore) DeleteSessionsByUser(ctx context.Context, userID id.UserID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, uuid.UUID(userID))
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
		_ = tx.Rollback()
	}()

	query := `
		SELECT id, user_id, client_id, tenant_id, requested_scope, status,
			last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
			device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions
		WHERE id = $1
		FOR UPDATE
	`
	session, err := scanSession(tx.QueryRowContext(ctx, query, uuid.UUID(sessionID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sentinel.ErrNotFound
		}
		return fmt.Errorf("find session for revoke: %w", err)
	}

	if !session.Revoke(now) {
		return ErrSessionRevoked
	}

	if err := s.updateSessionTx(ctx, tx, session); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revoke session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions removes all sessions that have expired as of the given time.
func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < $1`, now)
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
	query := `
		SELECT id, user_id, client_id, tenant_id, requested_scope, status,
			last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
			device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	sessions := make(map[id.SessionID]*models.Session)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions[session.ID] = session
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
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
		_ = tx.Rollback()
	}()

	query := `
		SELECT id, user_id, client_id, tenant_id, requested_scope, status,
			last_refreshed_at, last_access_token_jti, device_id, device_fingerprint_hash,
			device_display_name, approximate_location, created_at, expires_at, last_seen_at, revoked_at
		FROM sessions
		WHERE id = $1
		FOR UPDATE
	`
	session, err := scanSession(tx.QueryRowContext(ctx, query, uuid.UUID(sessionID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find session for execute: %w", err)
	}

	if err := validate(session); err != nil {
		return nil, err
	}

	mutate(session)
	if err := s.updateSessionTx(ctx, tx, session); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit session execute: %w", err)
	}
	return session, nil
}

type sessionRow interface {
	Scan(dest ...any) error
}

func scanSession(row sessionRow) (*models.Session, error) {
	var sessionID uuid.UUID
	var userID uuid.UUID
	var clientID uuid.UUID
	var tenantID uuid.UUID
	var requestedScopeBytes []byte
	var status string
	var lastRefreshedAt sql.NullTime
	var lastAccessTokenJTI string
	var deviceID string
	var deviceFingerprintHash string
	var deviceDisplayName string
	var approximateLocation string
	var createdAt time.Time
	var expiresAt time.Time
	var lastSeenAt time.Time
	var revokedAt sql.NullTime

	err := row.Scan(
		&sessionID,
		&userID,
		&clientID,
		&tenantID,
		&requestedScopeBytes,
		&status,
		&lastRefreshedAt,
		&lastAccessTokenJTI,
		&deviceID,
		&deviceFingerprintHash,
		&deviceDisplayName,
		&approximateLocation,
		&createdAt,
		&expiresAt,
		&lastSeenAt,
		&revokedAt,
	)
	if err != nil {
		return nil, err
	}

	var scopes []string
	if len(requestedScopeBytes) > 0 {
		if err := json.Unmarshal(requestedScopeBytes, &scopes); err != nil {
			return nil, fmt.Errorf("unmarshal session scopes: %w", err)
		}
	}

	session := &models.Session{
		ID:                  id.SessionID(sessionID),
		UserID:              id.UserID(userID),
		ClientID:            id.ClientID(clientID),
		TenantID:            id.TenantID(tenantID),
		RequestedScope:      scopes,
		Status:              models.SessionStatus(status),
		LastAccessTokenJTI:  lastAccessTokenJTI,
		DeviceID:            deviceID,
		DeviceFingerprintHash: deviceFingerprintHash,
		DeviceDisplayName:   deviceDisplayName,
		ApproximateLocation: approximateLocation,
		CreatedAt:           createdAt,
		ExpiresAt:           expiresAt,
		LastSeenAt:          lastSeenAt,
	}
	if lastRefreshedAt.Valid {
		session.LastRefreshedAt = &lastRefreshedAt.Time
	}
	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}
	return session, nil
}

func (s *PostgresStore) updateSessionTx(ctx context.Context, tx *sql.Tx, session *models.Session) error {
	scopeBytes, err := json.Marshal(session.RequestedScope)
	if err != nil {
		return fmt.Errorf("marshal session scopes: %w", err)
	}

	query := `
		UPDATE sessions
		SET user_id = $2,
			client_id = $3,
			tenant_id = $4,
			requested_scope = $5,
			status = $6,
			last_refreshed_at = $7,
			last_access_token_jti = $8,
			device_id = $9,
			device_fingerprint_hash = $10,
			device_display_name = $11,
			approximate_location = $12,
			created_at = $13,
			expires_at = $14,
			last_seen_at = $15,
			revoked_at = $16
		WHERE id = $1
	`
	res, err := tx.ExecContext(ctx, query,
		uuid.UUID(session.ID),
		uuid.UUID(session.UserID),
		uuid.UUID(session.ClientID),
		uuid.UUID(session.TenantID),
		scopeBytes,
		string(session.Status),
		nullTime(session.LastRefreshedAt),
		session.LastAccessTokenJTI,
		session.DeviceID,
		session.DeviceFingerprintHash,
		session.DeviceDisplayName,
		session.ApproximateLocation,
		session.CreatedAt,
		session.ExpiresAt,
		session.LastSeenAt,
		nullTime(session.RevokedAt),
	)
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
