package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"credo/internal/evidence/vc/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

// PostgresStore persists credentials in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed credential store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Save(ctx context.Context, credential models.CredentialRecord) error {
	claimsBytes, err := json.Marshal(credential.Claims)
	if err != nil {
		return fmt.Errorf("marshal credential claims: %w", err)
	}
	isOver18, verifiedVia := extractAgeOver18Claims(credential)
	query := `
		INSERT INTO vc_credentials (id, type, subject_id, issuer, issued_at, claims, is_over_18, verified_via)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			type = EXCLUDED.type,
			subject_id = EXCLUDED.subject_id,
			issuer = EXCLUDED.issuer,
			issued_at = EXCLUDED.issued_at,
			claims = EXCLUDED.claims,
			is_over_18 = EXCLUDED.is_over_18,
			verified_via = EXCLUDED.verified_via
	`
	_, err = s.db.ExecContext(ctx, query,
		credential.ID.String(),
		string(credential.Type),
		credential.Subject.String(),
		credential.Issuer,
		credential.IssuedAt,
		claimsBytes,
		isOver18,
		verifiedVia,
	)
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByID(ctx context.Context, credentialID models.CredentialID) (models.CredentialRecord, error) {
	query := `
		SELECT id, type, subject_id, issuer, issued_at,
			CASE WHEN type = 'AgeOver18' THEN NULL ELSE claims END AS claims,
			is_over_18, verified_via
		FROM vc_credentials
		WHERE id = $1
	`
	record, err := scanCredential(s.db.QueryRowContext(ctx, query, credentialID.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.CredentialRecord{}, sentinel.ErrNotFound
		}
		return models.CredentialRecord{}, fmt.Errorf("find credential by id: %w", err)
	}
	return record, nil
}

func (s *PostgresStore) FindBySubjectAndType(ctx context.Context, subject id.UserID, credType models.CredentialType) (models.CredentialRecord, error) {
	query := `
		SELECT id, type, subject_id, issuer, issued_at,
			CASE WHEN type = 'AgeOver18' THEN NULL ELSE claims END AS claims,
			is_over_18, verified_via
		FROM vc_credentials
		WHERE subject_id = $1 AND type = $2
		ORDER BY issued_at DESC
		LIMIT 1
	`
	record, err := scanCredential(s.db.QueryRowContext(ctx, query, subject.String(), string(credType)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.CredentialRecord{}, sentinel.ErrNotFound
		}
		return models.CredentialRecord{}, fmt.Errorf("find credential by subject and type: %w", err)
	}
	return record, nil
}

type credentialRow interface {
	Scan(dest ...any) error
}

func scanCredential(row credentialRow) (models.CredentialRecord, error) {
	var record models.CredentialRecord
	var subjectID string
	var claimsBytes []byte
	var isOver18 sql.NullBool
	var verifiedVia sql.NullString
	if err := row.Scan(&record.ID, &record.Type, &subjectID, &record.Issuer, &record.IssuedAt, &claimsBytes, &isOver18, &verifiedVia); err != nil {
		return models.CredentialRecord{}, err
	}

	parsedSubject, err := id.ParseUserID(subjectID)
	if err != nil {
		return models.CredentialRecord{}, fmt.Errorf("parse credential subject: %w", err)
	}
	record.Subject = parsedSubject

	var claims models.Claims
	if len(claimsBytes) > 0 {
		if err := json.Unmarshal(claimsBytes, &claims); err != nil {
			return models.CredentialRecord{}, fmt.Errorf("unmarshal credential claims: %w", err)
		}
	}
	if claims == nil {
		claims = models.Claims{}
	}
	if record.Type == models.CredentialTypeAgeOver18 {
		if isOver18.Valid {
			claims["is_over_18"] = isOver18.Bool
		}
		if verifiedVia.Valid && verifiedVia.String != "" {
			claims["verified_via"] = verifiedVia.String
		}
	}
	record.Claims = claims
	return record, nil
}

func extractAgeOver18Claims(credential models.CredentialRecord) (sql.NullBool, sql.NullString) {
	if credential.Type != models.CredentialTypeAgeOver18 {
		return sql.NullBool{}, sql.NullString{}
	}

	var isOver18 sql.NullBool
	var verifiedVia sql.NullString
	if value, ok := credential.Claims["is_over_18"].(bool); ok {
		isOver18 = sql.NullBool{Bool: value, Valid: true}
	}
	if value, ok := credential.Claims["verified_via"].(string); ok && value != "" {
		verifiedVia = sql.NullString{String: value, Valid: true}
	}
	return isOver18, verifiedVia
}
