package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresStore persists users in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres constructs a PostgreSQL-backed user store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Save(ctx context.Context, user *models.User) error {
	if user == nil {
		return fmt.Errorf("user is required")
	}

	query := `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			email = EXCLUDED.email,
			first_name = EXCLUDED.first_name,
			last_name = EXCLUDED.last_name,
			verified = EXCLUDED.verified,
			status = EXCLUDED.status,
			updated_at = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		uuid.UUID(user.ID),
		uuid.UUID(user.TenantID),
		user.Email,
		user.FirstName,
		user.LastName,
		user.Verified,
		string(user.Status),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("user already exists: %w", sentinel.ErrAlreadyUsed)
		}
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByID(ctx context.Context, userID id.UserID) (*models.User, error) {
	query := `
		SELECT id, tenant_id, email, first_name, last_name, verified, status
		FROM users
		WHERE id = $1
	`
	user, err := scanUser(s.db.QueryRowContext(ctx, query, uuid.UUID(userID)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return user, nil
}

func (s *PostgresStore) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, tenant_id, email, first_name, last_name, verified, status
		FROM users
		WHERE email = $1
		ORDER BY created_at ASC
		LIMIT 1
	`
	user, err := scanUser(s.db.QueryRowContext(ctx, query, email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return user, nil
}

// FindOrCreateByTenantAndEmail atomically finds a user by tenant and email or creates it if not found.
func (s *PostgresStore) FindOrCreateByTenantAndEmail(ctx context.Context, tenantID id.TenantID, email string, user *models.User) (*models.User, error) {
	if user == nil {
		return nil, fmt.Errorf("user is required")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin user upsert tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	insert := `
		INSERT INTO users (id, tenant_id, email, first_name, last_name, verified, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, email) DO NOTHING
	`
	_, err = tx.ExecContext(ctx, insert,
		uuid.UUID(user.ID),
		uuid.UUID(tenantID),
		email,
		user.FirstName,
		user.LastName,
		user.Verified,
		string(user.Status),
	)
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	query := `
		SELECT id, tenant_id, email, first_name, last_name, verified, status
		FROM users
		WHERE tenant_id = $1 AND email = $2
	`
	found, err := scanUser(tx.QueryRowContext(ctx, query, uuid.UUID(tenantID), email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find user after upsert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit user upsert: %w", err)
	}
	return found, nil
}

func (s *PostgresStore) Delete(ctx context.Context, userID id.UserID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, uuid.UUID(userID))
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
	}
	return nil
}

func (s *PostgresStore) ListAll(ctx context.Context) (map[id.UserID]*models.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, email, first_name, last_name, verified, status
		FROM users
	`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make(map[id.UserID]*models.User)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users[user.ID] = user
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return users, nil
}

// CountByTenant returns the number of users for a tenant.
func (s *PostgresStore) CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE tenant_id = $1`, uuid.UUID(tenantID)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count users by tenant: %w", err)
	}
	return count, nil
}

type userRow interface {
	Scan(dest ...any) error
}

func scanUser(row userRow) (*models.User, error) {
	var userID uuid.UUID
	var tenantID uuid.UUID
	var status string
	user := &models.User{}

	if err := row.Scan(&userID, &tenantID, &user.Email, &user.FirstName, &user.LastName, &user.Verified, &status); err != nil {
		return nil, err
	}

	user.ID = id.UserID(userID)
	user.TenantID = id.TenantID(tenantID)
	user.Status = models.UserStatus(status)
	return user, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
