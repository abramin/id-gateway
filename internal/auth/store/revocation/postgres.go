package revocation

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	authsqlc "credo/internal/auth/store/sqlc"
)

// PostgresTRL persists revoked token JTIs in PostgreSQL.
type PostgresTRL struct {
	db      *sql.DB
	queries *authsqlc.Queries
	clock   Clock // injected clock for testability (defaults to time.Now)
}

// PostgresTRLOption configures a PostgresTRL instance.
type PostgresTRLOption func(*PostgresTRL)

// WithPostgresClock sets the clock function for testability.
func WithPostgresClock(clock Clock) PostgresTRLOption {
	return func(trl *PostgresTRL) {
		if clock != nil {
			trl.clock = clock
		}
	}
}

// NewPostgresTRL constructs a PostgreSQL-backed token revocation list.
func NewPostgresTRL(db *sql.DB, opts ...PostgresTRLOption) *PostgresTRL {
	trl := &PostgresTRL{
		db:      db,
		queries: authsqlc.New(db),
		clock:   time.Now, // default to real time
	}
	for _, opt := range opts {
		if opt != nil {
			opt(trl)
		}
	}
	return trl
}

// RevokeToken adds a token to the revocation list with TTL.
func (t *PostgresTRL) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	if err := validateTTL(ttl); err != nil {
		return err
	}
	expiresAt := t.clock().Add(ttl)
	err := t.queries.UpsertTokenRevocation(ctx, authsqlc.UpsertTokenRevocationParams{
		Jti:       jti,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// IsRevoked checks if a token is in the revocation list.
func (t *PostgresTRL) IsRevoked(ctx context.Context, jti string) (bool, error) {
	expiresAt, err := t.queries.GetTokenRevocationExpiresAt(ctx, jti)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check token revocation: %w", err)
	}
	if t.clock().After(expiresAt) {
		return false, nil
	}
	return true, nil
}

// RevokeSessionTokens revokes multiple tokens associated with a session.
// Uses batch INSERT with unnest for efficiency instead of per-row inserts.
func (t *PostgresTRL) RevokeSessionTokens(ctx context.Context, sessionID string, jtis []string, ttl time.Duration) error {
	if len(jtis) == 0 {
		return nil
	}
	if err := validateTTL(ttl); err != nil {
		return err
	}

	// Filter empty JTIs
	validJTIs := make([]string, 0, len(jtis))
	for _, jti := range jtis {
		if jti != "" {
			validJTIs = append(validJTIs, jti)
		}
	}
	if len(validJTIs) == 0 {
		return nil
	}

	expiresAt := t.clock().Add(ttl)

	// Batch insert using unnest for O(1) round trips instead of O(n)
	err := t.queries.UpsertTokenRevocations(ctx, authsqlc.UpsertTokenRevocationsParams{
		Column1:   validJTIs,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("revoke session tokens batch: %w", err)
	}
	return nil
}
