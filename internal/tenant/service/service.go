package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"credo/internal/tenant/models"
	dErrors "credo/pkg/domain-errors"
)

const (
	clientStatusActive = "active"
)

type TenantStore interface {
	Create(ctx context.Context, tenant *models.Tenant) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}

type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// Service orchestrates tenant and client management.
type Service struct {
	tenants     TenantStore
	clients     ClientStore
	userCounter UserCounter
}

// New constructs a Service.
func New(tenants TenantStore, clients ClientStore, users UserCounter) *Service {
	return &Service{tenants: tenants, clients: clients, userCounter: users}
}

// CreateTenant registers a new tenant with validation.
func (s *Service) CreateTenant(ctx context.Context, name string) (*models.Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}
	existing, err := s.tenants.FindByName(ctx, name)
	if err != nil && !dErrors.Is(err, dErrors.CodeNotFound) {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to verify tenant uniqueness")
	}
	if existing != nil {
		return nil, dErrors.New(dErrors.CodeConflict, "tenant name must be unique")
	}

	t := &models.Tenant{ID: uuid.New(), Name: name, CreatedAt: time.Now()}
	if err := s.tenants.Create(ctx, t); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create tenant")
	}

	return t, nil
}

// GetTenant fetches tenant metadata with counts.
func (s *Service) GetTenant(ctx context.Context, id uuid.UUID) (*models.TenantDetails, error) {
	tenant, err := s.tenants.FindByID(ctx, id)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			return nil, dErrors.New(dErrors.CodeNotFound, "tenant not found")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to load tenant")
	}

	clientCount, err := s.clients.CountByTenant(ctx, id)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to count clients")
	}

	userCount := 0
	if s.userCounter != nil {
		userCount, err = s.userCounter.CountByTenant(ctx, id)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to count users")
		}
	}

	return &models.TenantDetails{Tenant: tenant, UserCount: userCount, ClientCount: clientCount}, nil
}

// CreateClient registers a client under a tenant.
func (s *Service) CreateClient(ctx context.Context, req *models.CreateClientRequest) (*models.ClientResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	if _, err := s.tenants.FindByID(ctx, req.TenantID); err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			return nil, dErrors.New(dErrors.CodeNotFound, "tenant not found")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to load tenant")
	}

	now := time.Now()
	secret := ""
	secretHash := ""
	var err error
	if !req.Public {
		secret, err = generateSecret()
		if err != nil {
			return nil, err
		}
		secretHash, err = hashSecret(secret)
		if err != nil {
			return nil, err
		}
	}

	client := &models.Client{
		ID:               uuid.New(),
		TenantID:         req.TenantID,
		Name:             req.Name,
		ClientID:         uuid.NewString(),
		ClientSecretHash: secretHash,
		RedirectURIs:     req.RedirectURIs,
		AllowedGrants:    req.AllowedGrants,
		AllowedScopes:    req.AllowedScopes,
		Status:           clientStatusActive,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create client")
	}

	return toResponse(client, secret), nil
}

// GetClient returns a registered client by id.
func (s *Service) GetClient(ctx context.Context, id uuid.UUID) (*models.ClientResponse, error) {
	client, err := s.clients.FindByID(ctx, id)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			return nil, dErrors.New(dErrors.CodeNotFound, "client not found")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get client")
	}
	return toResponse(client, ""), nil
}

// UpdateClient updates mutable fields and optionally rotates the secret.
func (s *Service) UpdateClient(ctx context.Context, id uuid.UUID, req *models.UpdateClientRequest) (*models.ClientResponse, error) {
	client, err := s.clients.FindByID(ctx, id)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			return nil, dErrors.New(dErrors.CodeNotFound, "client not found")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to get client")
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	if req.Name != nil {
		client.Name = strings.TrimSpace(*req.Name)
	}
	if req.RedirectURIs != nil {
		client.RedirectURIs = *req.RedirectURIs
	}
	if req.AllowedGrants != nil {
		client.AllowedGrants = *req.AllowedGrants
	}
	if req.AllowedScopes != nil {
		client.AllowedScopes = *req.AllowedScopes
	}

	rotatedSecret := ""
	if req.RotateSecret {
		rotatedSecret, err = generateSecret()
		if err != nil {
			return nil, err
		}
		client.ClientSecretHash, err = hashSecret(rotatedSecret)
		if err != nil {
			return nil, err
		}
	}

	client.UpdatedAt = time.Now()
	if err := s.clients.Update(ctx, client); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update client")
	}

	return toResponse(client, rotatedSecret), nil
}

func generateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", dErrors.Wrap(err, dErrors.CodeInternal, "could not generate client secret")
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashSecret(secret string) (string, error) {
	if secret == "" {
		return "", dErrors.New(dErrors.CodeValidation, "client secret cannot be empty")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", dErrors.New(dErrors.CodeValidation, "client secret is too long")
		}
		return "", dErrors.Wrap(err, dErrors.CodeInternal, "could not hash client secret")
	}
	return string(hashed), nil
}

func toResponse(client *models.Client, secret string) *models.ClientResponse {
	return &models.ClientResponse{
		ID:            client.ID,
		TenantID:      client.TenantID,
		Name:          client.Name,
		ClientID:      client.ClientID,
		ClientSecret:  secret,
		RedirectURIs:  client.RedirectURIs,
		AllowedGrants: client.AllowedGrants,
		AllowedScopes: client.AllowedScopes,
		Status:        client.Status,
		CreatedAt:     client.CreatedAt,
		UpdatedAt:     client.UpdatedAt,
	}
}
