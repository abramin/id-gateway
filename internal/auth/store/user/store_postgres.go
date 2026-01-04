package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"credo/internal/auth/models"
	authsqlc "credo/internal/auth/store/sqlc"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresStore persists users in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *authsqlc.Queries
}

// NewPostgres constructs a PostgreSQL-backed user store.
func NewPostgres(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: authsqlc.New(db),
	}
}

func (s *PostgresStore) Save(ctx context.Context, user *models.User) error {
	if user == nil {
		return fmt.Errorf("user is required")
	}

	err := s.queries.UpsertUser(ctx, authsqlc.UpsertUserParams{
		ID:        uuid.UUID(user.ID),
		TenantID:  uuid.UUID(user.TenantID),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Verified:  user.Verified,
		Status:    string(user.Status),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("user already exists: %w", sentinel.ErrAlreadyUsed)
		}
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func (s *PostgresStore) FindByID(ctx context.Context, userID id.UserID) (*models.User, error) {
	row, err := s.queries.GetUserByID(ctx, uuid.UUID(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return newUser(row.ID, row.TenantID, row.Email, row.FirstName, row.LastName, row.Verified, row.Status), nil
}

func (s *PostgresStore) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	row, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return newUser(row.ID, row.TenantID, row.Email, row.FirstName, row.LastName, row.Verified, row.Status), nil
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
		_ = tx.Rollback() //nolint:errcheck // rollback after commit is no-op; error already captured
	}()

	qtx := s.queries.WithTx(tx)
	err = qtx.InsertUserIfNotExists(ctx, authsqlc.InsertUserIfNotExistsParams{
		ID:        uuid.UUID(user.ID),
		TenantID:  uuid.UUID(tenantID),
		Email:     email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Verified:  user.Verified,
		Status:    string(user.Status),
	})
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}

	row, err := qtx.GetUserByTenantEmail(ctx, authsqlc.GetUserByTenantEmailParams{
		TenantID: uuid.UUID(tenantID),
		Email:    email,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found: %w", sentinel.ErrNotFound)
		}
		return nil, fmt.Errorf("find user after upsert: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit user upsert: %w", err)
	}
	return newUser(row.ID, row.TenantID, row.Email, row.FirstName, row.LastName, row.Verified, row.Status), nil
}

func (s *PostgresStore) Delete(ctx context.Context, userID id.UserID) error {
	res, err := s.queries.DeleteUserByID(ctx, uuid.UUID(userID))
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
	rows, err := s.queries.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	users := make(map[id.UserID]*models.User, len(rows))
	for _, row := range rows {
		user := newUser(row.ID, row.TenantID, row.Email, row.FirstName, row.LastName, row.Verified, row.Status)
		users[user.ID] = user
	}
	return users, nil
}

// CountByTenant returns the number of users for a tenant.
func (s *PostgresStore) CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error) {
	count, err := s.queries.CountUsersByTenant(ctx, uuid.UUID(tenantID))
	if err != nil {
		return 0, fmt.Errorf("count users by tenant: %w", err)
	}
	return int(count), nil
}

func newUser(userID uuid.UUID, tenantID uuid.UUID, email, firstName, lastName string, verified bool, status string) *models.User {
	return &models.User{
		ID:        id.UserID(userID),
		TenantID:  id.TenantID(tenantID),
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Verified:  verified,
		Status:    models.UserStatus(status),
	}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
