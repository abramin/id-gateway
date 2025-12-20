package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/platform/metrics"
	"credo/internal/platform/middleware"
	"credo/internal/sentinel"
	"credo/internal/tenant/models"
	"credo/pkg/attrs"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/secrets"
)

type TenantStore interface {
	CreateIfNameAvailable(ctx context.Context, tenant *models.Tenant) error
	FindByID(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error)
	FindByName(ctx context.Context, name string) (*models.Tenant, error)
	Count(ctx context.Context) (int, error)
}

type ClientStore interface {
	Create(ctx context.Context, client *models.Client) error
	Update(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, clientID id.ClientID) (*models.Client, error)
	FindByTenantAndID(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error)
	FindByOAuthClientID(ctx context.Context, oauthClientID string) (*models.Client, error)
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
}

type UserCounter interface {
	CountByTenant(ctx context.Context, tenantID id.TenantID) (int, error)
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

	t, err := models.NewTenant(id.TenantID(uuid.New()), name)
	if err != nil {
		return nil, err
	}

	if err := s.tenants.CreateIfNameAvailable(ctx, t); err != nil {
		if errors.Is(err, sentinel.ErrAlreadyUsed) || dErrors.HasCode(err, dErrors.CodeConflict) {
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
func (s *Service) GetTenant(ctx context.Context, tenantID id.TenantID) (*models.TenantDetails, error) {
	if tenantID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "tenant ID required")
	}
	tenant, err := s.tenants.FindByID(ctx, tenantID)
	if err != nil {
		return nil, wrapTenantErr(err, "failed to load tenant")
	}

	clientCount, err := s.clients.CountByTenant(ctx, tenantID)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to count clients")
	}

	userCount := 0
	if s.userCounter != nil {
		userCount, err = s.userCounter.CountByTenant(ctx, tenantID)
		if err != nil {
			return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to count users")
		}
	}

	return &models.TenantDetails{
		ID:          tenant.ID,
		Name:        tenant.Name,
		Status:      tenant.Status,
		CreatedAt:   tenant.CreatedAt,
		UserCount:   userCount,
		ClientCount: clientCount,
	}, nil
}

// CreateClient registers a client under a tenant.
// Returns the created client and the cleartext secret (only available at creation time).
func (s *Service) CreateClient(ctx context.Context, req *models.CreateClientRequest) (*models.Client, string, error) {
	req.Normalize()
	if err := req.Validate(); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeValidation, "invalid client request")
	}

	if _, err := s.tenants.FindByID(ctx, req.TenantID); err != nil {
		return nil, "", wrapTenantErr(err, "failed to load tenant")
	}

	secret, secretHash, err := generateSecret(req.Public)
	if err != nil {
		return nil, "", err
	}

	client, err := models.NewClient(
		id.ClientID(uuid.New()),
		req.TenantID,
		req.Name,
		uuid.NewString(),
		secretHash,
		req.RedirectURIs,
		req.AllowedGrants,
		req.AllowedScopes,
		time.Now(),
	)
	if err != nil {
		return nil, "", err
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to create client")
	}

	s.logAudit(ctx, string(audit.EventClientCreated),
		"tenant_id", client.TenantID,
		"client_id", client.ID,
		"client_name", client.Name,
	)

	return client, secret, nil
}

// GetClient returns a registered client by id.
func (s *Service) GetClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	if clientID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, wrapClientErr(err, "failed to get client")
	}
	return client, nil
}

// GetClientForTenant enforces tenant scoping when retrieving a client.
func (s *Service) GetClientForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	if tenantID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "tenant ID required")
	}
	if clientID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByTenantAndID(ctx, tenantID, clientID)
	if err != nil {
		return nil, wrapClientErr(err, "failed to get client")
	}
	return client, nil
}

// UpdateClient updates mutable fields and optionally rotates the secret.
// Returns the updated client and the rotated secret (empty if not rotated).
func (s *Service) UpdateClient(ctx context.Context, clientID id.ClientID, req *models.UpdateClientRequest) (*models.Client, string, error) {
	if clientID.IsNil() {
		return nil, "", dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, "", wrapClientErr(err, "failed to get client")
	}
	return s.applyClientUpdate(ctx, client, req)
}

// UpdateClientForTenant enforces tenant scoping when updating a client.
// Returns the updated client and the rotated secret (empty if not rotated).
func (s *Service) UpdateClientForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, req *models.UpdateClientRequest) (*models.Client, string, error) {
	if tenantID.IsNil() {
		return nil, "", dErrors.New(dErrors.CodeBadRequest, "tenant ID required")
	}
	if clientID.IsNil() {
		return nil, "", dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByTenantAndID(ctx, tenantID, clientID)
	if err != nil {
		return nil, "", wrapClientErr(err, "failed to get client")
	}
	return s.applyClientUpdate(ctx, client, req)
}

// applyClientUpdate contains the shared update logic for client modifications.
func (s *Service) applyClientUpdate(ctx context.Context, client *models.Client, req *models.UpdateClientRequest) (*models.Client, string, error) {
	req.Normalize()
	if err := req.Validate(); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeValidation, "invalid update request")
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
		var err error
		rotatedSecret, client.ClientSecretHash, err = generateSecret(false)
		if err != nil {
			return nil, "", err
		}
	}

	client.UpdatedAt = time.Now()
	if err := s.clients.Update(ctx, client); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to update client")
	}

	if req.RotateSecret {
		s.logAudit(ctx, string(audit.EventSecretRotated),
			"tenant_id", client.TenantID,
			"client_id", client.ID,
		)
	}

	return client, rotatedSecret, nil
}

// ResolveClient maps client_id -> client and tenant as a single choke point.
func (s *Service) ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, nil, dErrors.New(dErrors.CodeValidation, "client_id is required")
	}

	client, err := s.clients.FindByOAuthClientID(ctx, clientID)
	if err != nil {
		return nil, nil, wrapClientErr(err, "failed to resolve client")
	}
	if !client.IsActive() {
		return nil, nil, dErrors.New(dErrors.CodeInvalidClient, "client is inactive")
	}

	tenant, err := s.tenants.FindByID(ctx, client.TenantID)
	if err != nil {
		return nil, nil, wrapTenantErr(err, "failed to load tenant for client")
	}
	return client, tenant, nil
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
	userIDStr := attrs.ExtractString(attributes, "user_id")
	userID, _ := id.ParseUserID(userIDStr) // Best-effort for audit - ignore parse errors
	_ = s.auditPublisher.Emit(ctx, audit.Event{
		UserID:  userID,
		Subject: userIDStr,
		Action:  event,
	})
}

func (s *Service) incrementTenantCreated() {
	if s.metrics != nil {
		s.metrics.TenantCreated.Inc()
	}
}

func wrapClientErr(err error, action string) error {
	if errors.Is(err, sentinel.ErrNotFound) {
		return dErrors.New(dErrors.CodeNotFound, "client not found")
	}
	return dErrors.Wrap(err, dErrors.CodeInternal, action)
}

func wrapTenantErr(err error, action string) error {
	if errors.Is(err, sentinel.ErrNotFound) {
		return dErrors.New(dErrors.CodeNotFound, "tenant not found")
	}
	return dErrors.Wrap(err, dErrors.CodeInternal, action)
}

// generateSecret creates a new secret and its hash.
// Returns empty strings for public clients.
func generateSecret(isPublic bool) (secret, hash string, err error) {
	if isPublic {
		return "", "", nil
	}
	secret, err = secrets.Generate()
	if err != nil {
		return "", "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate secret")
	}
	hash, err = secrets.Hash(secret)
	if err != nil {
		return "", "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to hash secret")
	}
	return secret, hash, nil
}
