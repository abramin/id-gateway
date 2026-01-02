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
	txcontext "credo/pkg/platform/tx"

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

type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *PostgresStore) execer(ctx context.Context) dbExecutor {
	if tx, ok := txcontext.From(ctx); ok {
		return tx
	}
	return s.db
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
	_, err = s.execer(ctx).ExecContext(ctx, query,
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
	res, err := s.execer(ctx).ExecContext(ctx, query,
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
	client, err := scanClient(s.execer(ctx).QueryRowContext(ctx, query, uuid.UUID(clientID)))
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
	client, err := scanClient(s.execer(ctx).QueryRowContext(ctx, query, uuid.UUID(clientID), uuid.UUID(tenantID)))
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
	client, err := scanClient(s.execer(ctx).QueryRowContext(ctx, query, oauthClientID))
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
	if err := s.execer(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE tenant_id = $1`, uuid.UUID(tenantID)).Scan(&count); err != nil {
		return 0, fmt.Errorf("count clients by tenant: %w", err)
	}
	return count, nil
}

type clientRow interface {
	Scan(dest ...any) error
}

func scanClient(row clientRow) (*models.Client, error) {
	var (
		clientID, tenantID         uuid.UUID
		secret                     sql.NullString
		redirectBytes, grantsBytes []byte
		scopesBytes                []byte
		status                     string
		client                     models.Client
	)

	if err := row.Scan(
		&clientID, &tenantID,
		&client.Name, &client.OAuthClientID, &secret,
		&redirectBytes, &grantsBytes, &scopesBytes,
		&status, &client.CreatedAt, &client.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if secret.Valid {
		client.ClientSecretHash = secret.String
	}
	if err := unmarshalJSONIfPresent(redirectBytes, &client.RedirectURIs, "redirect_uris"); err != nil {
		return nil, err
	}
	if err := unmarshalJSONIfPresent(grantsBytes, &client.AllowedGrants, "allowed_grants"); err != nil {
		return nil, err
	}
	if err := unmarshalJSONIfPresent(scopesBytes, &client.AllowedScopes, "allowed_scopes"); err != nil {
		return nil, err
	}

	client.ID = id.ClientID(clientID)
	client.TenantID = id.TenantID(tenantID)
	client.Status = models.ClientStatus(status)
	return &client, nil
}

// unmarshalJSONIfPresent unmarshals JSON data into target if data is non-empty.
func unmarshalJSONIfPresent[T any](data []byte, target *T, field string) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("unmarshal %s: %w", field, err)
	}
	return nil
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
