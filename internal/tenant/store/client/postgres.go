package client

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"credo/internal/tenant/models"
	tenantsqlc "credo/internal/tenant/store/sqlc"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
	txcontext "credo/pkg/platform/tx"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresStore persists OAuth clients in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *tenantsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed client store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: tenantsqlc.New(db),
	}
}

func (s *PostgresStore) queriesFor(ctx context.Context) *tenantsqlc.Queries {
	if tx, ok := txcontext.From(ctx); ok {
		return s.queries.WithTx(tx)
	}
	return s.queries
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

	err = s.queriesFor(ctx).CreateClient(ctx, tenantsqlc.CreateClientParams{
		ID:               uuid.UUID(client.ID),
		TenantID:         uuid.UUID(client.TenantID),
		Name:             client.Name,
		OauthClientID:    client.OAuthClientID,
		ClientSecretHash: nullString(client.ClientSecretHash),
		RedirectUris:     redirectURIs,
		AllowedGrants:    allowedGrants,
		AllowedScopes:    allowedScopes,
		Status:           string(client.Status),
		CreatedAt:        client.CreatedAt,
		UpdatedAt:        client.UpdatedAt,
	})
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
	return s.updateClient(ctx, s.queriesFor(ctx), client)
}

// Execute atomically validates and mutates a client under lock.
func (s *PostgresStore) Execute(ctx context.Context, clientID id.ClientID, validate func(*models.Client) error, mutate func(*models.Client)) (*models.Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin client execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	row, err := qtx.GetClientForUpdate(ctx, uuid.UUID(clientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client for execute: %w", err)
	}

	client, err := toClient(row)
	if err != nil {
		return nil, fmt.Errorf("scan client: %w", err)
	}
	if err := validate(client); err != nil {
		return nil, err
	}

	mutate(client)
	if err := s.updateClient(ctx, qtx, client); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit client execute: %w", err)
	}
	return client, nil
}

func (s *PostgresStore) updateClient(ctx context.Context, queries *tenantsqlc.Queries, client *models.Client) error {
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

	res, err := queries.UpdateClient(ctx, tenantsqlc.UpdateClientParams{
		ID:               uuid.UUID(client.ID),
		Name:             client.Name,
		OauthClientID:    client.OAuthClientID,
		ClientSecretHash: nullString(client.ClientSecretHash),
		RedirectUris:     redirectURIs,
		AllowedGrants:    allowedGrants,
		AllowedScopes:    allowedScopes,
		Status:           string(client.Status),
		UpdatedAt:        client.UpdatedAt,
	})
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
	row, err := s.queriesFor(ctx).GetClientByID(ctx, uuid.UUID(clientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client by id: %w", err)
	}
	return toClient(row)
}

// FindByTenantAndID retrieves a client scoped to a specific tenant.
func (s *PostgresStore) FindByTenantAndID(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	row, err := s.queriesFor(ctx).GetClientByTenantAndID(ctx, tenantsqlc.GetClientByTenantAndIDParams{
		ID:       uuid.UUID(clientID),
		TenantID: uuid.UUID(tenantID),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client by tenant and id: %w", err)
	}
	return toClient(row)
}

// FindByOAuthClientID retrieves a client by its OAuth client_id.
func (s *PostgresStore) FindByOAuthClientID(ctx context.Context, oauthClientID string) (*models.Client, error) {
	row, err := s.queriesFor(ctx).GetClientByOAuthClientID(ctx, oauthClientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find client by oauth_client_id: %w", err)
	}
	return toClient(row)
}

// CountByTenant returns the number of clients registered under a tenant.
func (s *PostgresStore) CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error) {
	count, err := s.queriesFor(ctx).CountClientsByTenant(ctx, uuid.UUID(tenantID))
	if err != nil {
		return 0, fmt.Errorf("count clients by tenant: %w", err)
	}
	return int(count), nil
}

func toClient(row tenantsqlc.Client) (*models.Client, error) {
	client := &models.Client{
		ID:            id.ClientID(row.ID),
		TenantID:      id.TenantID(row.TenantID),
		Name:          row.Name,
		OAuthClientID: row.OauthClientID,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
		Status:        models.ClientStatus(row.Status),
	}
	if row.ClientSecretHash.Valid {
		client.ClientSecretHash = row.ClientSecretHash.String
	}
	if err := unmarshalJSONIfPresent([]byte(row.RedirectUris), &client.RedirectURIs, "redirect_uris"); err != nil {
		return nil, err
	}
	if err := unmarshalJSONIfPresent([]byte(row.AllowedGrants), &client.AllowedGrants, "allowed_grants"); err != nil {
		return nil, err
	}
	if err := unmarshalJSONIfPresent([]byte(row.AllowedScopes), &client.AllowedScopes, "allowed_scopes"); err != nil {
		return nil, err
	}
	return client, nil
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
