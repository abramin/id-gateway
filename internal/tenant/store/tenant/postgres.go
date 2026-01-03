package tenant

import (
	"context"
	"database/sql"
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

// PostgresStore persists tenants in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *tenantsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed tenant store.
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

// CreateIfNameAvailable atomically creates the tenant if the name is not already taken (case-insensitive).
func (s *PostgresStore) CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is required")
	}
	err := s.queriesFor(ctx).CreateTenant(ctx, tenantsqlc.CreateTenantParams{
		ID:        uuid.UUID(tenant.ID),
		Name:      tenant.Name,
		Status:    string(tenant.Status),
		CreatedAt: tenant.CreatedAt,
		UpdatedAt: tenant.UpdatedAt,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("tenant name must be unique: %w", sentinel.ErrAlreadyUsed)
		}
		return fmt.Errorf("create tenant: %w", err)
	}
	return nil
}

// FindByID retrieves a tenant by its UUID.
func (s *PostgresStore) FindByID(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error) {
	row, err := s.queriesFor(ctx).GetTenantByID(ctx, uuid.UUID(tenantID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find tenant by id: %w", err)
	}
	return toTenant(row), nil
}

// FindByName retrieves a tenant by name (case-insensitive).
func (s *PostgresStore) FindByName(ctx context.Context, name string) (*models.Tenant, error) {
	row, err := s.queriesFor(ctx).GetTenantByName(ctx, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find tenant by name: %w", err)
	}
	return toTenant(row), nil
}

// Count returns the total number of tenants.
func (s *PostgresStore) Count(ctx context.Context) (int, error) {
	count, err := s.queriesFor(ctx).CountTenants(ctx)
	if err != nil {
		return 0, fmt.Errorf("count tenants: %w", err)
	}
	return int(count), nil
}

// Update updates an existing tenant.
func (s *PostgresStore) Update(ctx context.Context, tenant *models.Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is required")
	}
	res, err := s.queriesFor(ctx).UpdateTenant(ctx, tenantsqlc.UpdateTenantParams{
		ID:        uuid.UUID(tenant.ID),
		Name:      tenant.Name,
		Status:    string(tenant.Status),
		UpdatedAt: tenant.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("update tenant: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update tenant rows: %w", err)
	}
	if rows == 0 {
		return sentinel.ErrNotFound
	}
	return nil
}

// Execute atomically validates and mutates a tenant under lock.
func (s *PostgresStore) Execute(ctx context.Context, tenantID id.TenantID, validate func(*models.Tenant) error, mutate func(*models.Tenant)) (*models.Tenant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tenant execute tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	qtx := s.queries.WithTx(tx)
	row, err := qtx.GetTenantForUpdate(ctx, uuid.UUID(tenantID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find tenant for execute: %w", err)
	}

	tenant := toTenant(row)
	if err := validate(tenant); err != nil {
		return nil, err
	}

	mutate(tenant)
	res, err := qtx.UpdateTenant(ctx, tenantsqlc.UpdateTenantParams{
		ID:        uuid.UUID(tenant.ID),
		Name:      tenant.Name,
		Status:    string(tenant.Status),
		UpdatedAt: tenant.UpdatedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("update tenant rows: %w", err)
	}
	if rows == 0 {
		return nil, sentinel.ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tenant execute: %w", err)
	}
	return tenant, nil
}

func toTenant(row tenantsqlc.Tenant) *models.Tenant {
	return &models.Tenant{
		ID:        id.TenantID(row.ID),
		Name:      row.Name,
		Status:    models.TenantStatus(row.Status),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
