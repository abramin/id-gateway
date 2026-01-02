package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresStore persists tenants in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed tenant store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// CreateIfNameAvailable atomically creates the tenant if the name is not already taken (case-insensitive).
func (s *PostgresStore) CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is required")
	}
	query := `
		INSERT INTO tenants (id, name, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := s.db.ExecContext(ctx, query,
		uuid.UUID(tenant.ID),
		tenant.Name,
		string(tenant.Status),
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)
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
	query := `
		SELECT id, name, status, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`
	tenant, err := scanTenant(s.db.QueryRowContext(ctx, query, uuid.UUID(tenantID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find tenant by id: %w", err)
	}
	return tenant, nil
}

// FindByName retrieves a tenant by name (case-insensitive).
func (s *PostgresStore) FindByName(ctx context.Context, name string) (*models.Tenant, error) {
	query := `
		SELECT id, name, status, created_at, updated_at
		FROM tenants
		WHERE lower(name) = lower($1)
	`
	tenant, err := scanTenant(s.db.QueryRowContext(ctx, query, name))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sentinel.ErrNotFound
		}
		return nil, fmt.Errorf("find tenant by name: %w", err)
	}
	return tenant, nil
}

// Count returns the total number of tenants.
func (s *PostgresStore) Count(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count tenants: %w", err)
	}
	return count, nil
}

// Update updates an existing tenant.
func (s *PostgresStore) Update(ctx context.Context, tenant *models.Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is required")
	}
	query := `
		UPDATE tenants
		SET name = $2, status = $3, updated_at = $4
		WHERE id = $1
	`
	res, err := s.db.ExecContext(ctx, query,
		uuid.UUID(tenant.ID),
		tenant.Name,
		string(tenant.Status),
		tenant.UpdatedAt,
	)
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

type tenantRow interface {
	Scan(dest ...any) error
}

func scanTenant(row tenantRow) (*models.Tenant, error) {
	var tenant models.Tenant
	var status string
	var tenantID uuid.UUID
	if err := row.Scan(&tenantID, &tenant.Name, &status, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
		return nil, err
	}
	tenant.ID = id.TenantID(tenantID)
	tenant.Status = models.TenantStatus(status)
	return &tenant, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
