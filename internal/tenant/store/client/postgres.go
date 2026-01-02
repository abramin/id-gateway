package client

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresStore persists OAuth clients in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed client store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Create persists a new client.
func (s *PostgresStore) Create(ctx context.Context, client *models.Client) error {
	if client == nil {
		return fmt.Errorf("client is required")
	}
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshal redirect uris: %w", err)
	}
	allowedGrants, err := json.Marshal(client.AllowedGrants)
	if err != nil {
		return fmt.Errorf("marshal allowed grants: %w", err)
	}
	allowedScopes, err := json.Marshal(client.AllowedScopes)
	if err != nil {
		return fmt.Errorf("marshal allowed scopes: %w", err)
	}

	query := `
		INSERT INTO clients (
			id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
			allowed_grants, allowed_scopes, status, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err = s.db.ExecContext(ctx, query,
		uuid.UUID(client.ID),
		uuid.UUID(client.TenantID),
		client.Name,
		client.OAuthClientID,
		nullString(client.ClientSecretHash),
		redirectURIs,
		allowedGrants,
		allowedScopes,
		string(client.Status),
		client.CreatedAt,
		client.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("client already exists: %w", sentinel.ErrAlreadyUsed)
		}
		return fmt.Errorf("create client: %w", err)
	}
	return nil
}

// Update persists changes to an existing client.
func (s *PostgresStore) Update(ctx context.Context, client *models.Client) error {
	if client == nil {
		return fmt.Errorf("client is required")
	}
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshal redirect uris: %w", err)
	}
	allowedGrants, err := json.Marshal(client.AllowedGrants)
	if err != nil {
		return fmt.Errorf("marshal allowed grants: %w", err)
	}
	allowedScopes, err := json.Marshal(client.AllowedScopes)
	if err != nil {
		return fmt.Errorf("marshal allowed scopes: %w", err)
	}

	query := `
		UPDATE clients
		SET name = $2,
			oauth_client_id = $3,
			client_secret_hash = $4,
			redirect_uris = $5,
			allowed_grants = $6,
			allowed_scopes = $7,
			status = $8,
			updated_at = $9
		WHERE id = $1
	`
	res, err := s.db.ExecContext(ctx, query,
		uuid.UUID(client.ID),
		client.Name,
		client.OAuthClientID,
		nullString(client.ClientSecretHash),
		redirectURIs,
		allowedGrants,
		allowedScopes,
		string(client.Status),
		client.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update client rows: %w", err)
	}
	if rows == 0 {
		return sentinel.ErrNotFound
	}
	return nil
}

// FindByID retrieves a client by its internal UUID.
func (s *PostgresStore) FindByID(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	query := `
		SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
			allowed_grants, allowed_scopes, status, created_at, updated_at
		FROM clients
		WHERE id = $1
	`
	client, err := scanClient(s.db.QueryRowContext(ctx, query, uuid.UUID(clientID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client by id: %w", err)
	}
	return client, nil
}

// FindByTenantAndID retrieves a client scoped to a specific tenant.
func (s *PostgresStore) FindByTenantAndID(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	query := `
		SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
			allowed_grants, allowed_scopes, status, created_at, updated_at
		FROM clients
		WHERE id = $1 AND tenant_id = $2
	`
	client, err := scanClient(s.db.QueryRowContext(ctx, query, uuid.UUID(clientID), uuid.UUID(tenantID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client by tenant and id: %w", err)
	}
	return client, nil
}

// FindByOAuthClientID retrieves a client by its OAuth client_id.
func (s *PostgresStore) FindByOAuthClientID(ctx context.Context, oauthClientID string) (*models.Client, error) {
	query := `
		SELECT id, tenant_id, name, oauth_client_id, client_secret_hash, redirect_uris,
			allowed_grants, allowed_scopes, status, created_at, updated_at
		FROM clients
		WHERE oauth_client_id = $1
	`
	client, err := scanClient(s.db.QueryRowContext(ctx, query, oauthClientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client by oauth_client_id: %w", err)
	}
	return client, nil
}

// CountByTenant returns the number of clients registered under a tenant.
func (s *PostgresStore) CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE tenant_id = $1`, uuid.UUID(tenantID)).Scan(&count); err != nil {
		return 0, fmt.Errorf("count clients by tenant: %w", err)
	}
	return count, nil
}

type clientRow interface {
	Scan(dest ...any) error
}

func scanClient(row clientRow) (*models.Client, error) {
	var client models.Client
	var tenantID uuid.UUID
	var clientID uuid.UUID
	var secret sql.NullString
	var redirectBytes []byte
	var grantsBytes []byte
	var scopesBytes []byte
	var status string

	err := row.Scan(
		&clientID,
		&tenantID,
		&client.Name,
		&client.OAuthClientID,
		&secret,
		&redirectBytes,
		&grantsBytes,
		&scopesBytes,
		&status,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if secret.Valid {
		client.ClientSecretHash = secret.String
	}
	if len(redirectBytes) > 0 {
		if err := json.Unmarshal(redirectBytes, &client.RedirectURIs); err != nil {
			return nil, fmt.Errorf("unmarshal redirect uris: %w", err)
		}
	}
	if len(grantsBytes) > 0 {
		if err := json.Unmarshal(grantsBytes, &client.AllowedGrants); err != nil {
			return nil, fmt.Errorf("unmarshal allowed grants: %w", err)
		}
	}
	if len(scopesBytes) > 0 {
		if err := json.Unmarshal(scopesBytes, &client.AllowedScopes); err != nil {
			return nil, fmt.Errorf("unmarshal allowed scopes: %w", err)
		}
	}

	client.ID = id.ClientID(clientID)
	client.TenantID = id.TenantID(tenantID)
	client.Status = models.ClientStatus(status)
	return &client, nil
}

func nullString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
