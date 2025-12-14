package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"
	"credo/internal/tenant/models"
	"credo/pkg/attrs"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/secrets"
)

const (
	clientStatusActive   = "active"
	clientStatusDisabled = "disabled"
)

type TenantStore interface {
	CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, id uuid.UUID) (*models.Client, error)
	FindByClientID(ctx context.Context, clientID string) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}

type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
}

type AuditPublisher interface {
	Emit(ctx context.Context, base audit.Event) error
}

// Service orchestrates tenant and client management.
type Service struct {
	tenants        TenantStore
	clients        ClientStore
	userCounter    UserCounter
	logger         *slog.Logger
	auditPublisher AuditPublisher
	metrics        *metrics.Metrics
}

type Option func(s *Service)

func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		s.logger = logger
	}
}

func WithAuditPublisher(publisher AuditPublisher) Option {
	return func(s *Service) {
		s.auditPublisher = publisher
	}
}

func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Service) {
		s.metrics = m
	}
}

// New constructs a Service.
func New(tenants TenantStore, clients ClientStore, users UserCounter, opts ...Option) *Service {
	s := &Service{tenants: tenants, clients: clients, userCounter: users}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Service) CreateTenant(ctx context.Context, name string) (*models.Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, dErrors.New(dErrors.CodeValidation, "name is required")
	}
	if len(name) > 128 {
		return nil, dErrors.New(dErrors.CodeValidation, "name must be 128 characters or less")
	}

	t := &models.Tenant{ID: uuid.New(), Name: name, CreatedAt: time.Now()}
	if err := s.tenants.CreateIfNameAvailable(ctx, t); err != nil {
		if dErrors.Is(err, dErrors.CodeConflict) {
			return nil, dErrors.New(dErrors.CodeConflict, "tenant name must be unique")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create tenant")
	}
	s.logAudit(ctx, string(audit.EventTenantCreated),
		"tenant_id", t.ID)
	s.incrementTenantCreated()

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
	req.Normalize()
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
		secret, err = secrets.Generate()
		if err != nil {
			return nil, err
		}
		secretHash, err = secrets.Hash(secret)
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

// GetClientForTenant enforces tenant scoping when retrieving a client.
func (s *Service) GetClientForTenant(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*models.ClientResponse, error) {
	client, err := s.GetClient(ctx, id)
	if err != nil {
		return nil, err
	}
	if client.TenantID != tenantID {
		return nil, dErrors.New(dErrors.CodeNotFound, "client not found")
	}
	return client, nil
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

	req.Normalize()
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
		rotatedSecret, err = secrets.Generate()
		if err != nil {
			return nil, err
		}
		client.ClientSecretHash, err = secrets.Hash(rotatedSecret)
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

// UpdateClientForTenant enforces tenant scoping when updating a client.
func (s *Service) UpdateClientForTenant(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, req *models.UpdateClientRequest) (*models.ClientResponse, error) {
	resp, err := s.UpdateClient(ctx, id, req)
	if err != nil {
		return nil, err
	}
	if resp.TenantID != tenantID {
		return nil, dErrors.New(dErrors.CodeNotFound, "client not found")
	}
	return resp, nil
}

// ResolveClient maps client_id -> client and tenant as a single choke point.
func (s *Service) ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, nil, dErrors.New(dErrors.CodeValidation, "client_id is required")
	}

	client, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			return nil, nil, dErrors.New(dErrors.CodeNotFound, "client not found")
		}
		return nil, nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to resolve client")
	}
	if client.Status != clientStatusActive {
		return nil, nil, dErrors.New(dErrors.CodeForbidden, "client is disabled")
	}

	tenant, err := s.tenants.FindByID(ctx, client.TenantID)
	if err != nil {
		if dErrors.Is(err, dErrors.CodeNotFound) {
			return nil, nil, dErrors.New(dErrors.CodeNotFound, "tenant not found")
		}
		return nil, nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to load tenant for client")
	}
	return client, tenant, nil
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

func (s *Service) logAudit(ctx context.Context, event string, attributes ...any) {
	// Add request_id from context if available
	if requestID := middleware.GetRequestID(ctx); requestID != "" {
		attributes = append(attributes, "request_id", requestID)
	}
	args := append(attributes, "event", event, "log_type", "audit")
	if s.logger != nil {
		s.logger.InfoContext(ctx, event, args...)
	}
	if s.auditPublisher == nil {
		return
	}
	userID := attrs.ExtractString(attributes, "user_id")
	_ = s.auditPublisher.Emit(ctx, audit.Event{
		UserID:  userID,
		Subject: userID,
		Action:  event,
	})
}

func (s *Service) incrementTenantCreated() {
	if s.metrics != nil {
		s.metrics.TenantCreated.Inc()
	}
}
