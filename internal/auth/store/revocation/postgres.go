package revocation

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PostgresTRL persists revoked token JTIs in PostgreSQL.
type PostgresTRL struct {
	db *sql.DB
}

// NewPostgresTRL constructs a PostgreSQL-backed token revocation list.
func NewPostgresTRL(db *sql.DB) *PostgresTRL {
	return &PostgresTRL{db: db}
}

// RevokeToken adds a token to the revocation list with TTL.
func (t *PostgresTRL) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	expiresAt := time.Now().Add(ttl)
	query := `
		INSERT INTO token_revocations (jti, expires_at)
		VALUES ($1, $2)
		ON CONFLICT (jti) DO UPDATE SET
			expires_at = EXCLUDED.expires_at
	`
	_, err := t.db.ExecContext(ctx, query, jti, expiresAt)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// IsRevoked checks if a token is in the revocation list.
func (t *PostgresTRL) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var expiresAt time.Time
	err := t.db.QueryRowContext(ctx, `SELECT expires_at FROM token_revocations WHERE jti = $1`, jti).Scan(&expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check token revocation: %w", err)
	}
	if time.Now().After(expiresAt) {
		return false, nil
	}
	return true, nil
}

// RevokeSessionTokens revokes multiple tokens associated with a session.
func (t *PostgresTRL) RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error {
	if len(jtis) == 0 {
		return nil
	}
	expiresAt := time.Now().Add(ttl)

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revoke session tokens tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	query := `
		INSERT INTO token_revocations (jti, expires_at)
		VALUES ($1, $2)
		ON CONFLICT (jti) DO UPDATE SET
			expires_at = EXCLUDED.expires_at
	`
	for _, jti := range jtis {
		if _, err := tx.ExecContext(ctx, query, jti, expiresAt); err != nil {
			return fmt.Errorf("revoke session token: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revoke session tokens: %w", err)
	}
	return nil
}
