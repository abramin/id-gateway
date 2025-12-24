package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	tenantmetrics "credo/internal/tenant/metrics"
	"credo/internal/tenant/models"
	"credo/internal/tenant/secrets"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// ClientService orchestrates client registration and lifecycle management.
type ClientService struct {
	clients      ClientStore
	tenants      TenantStore // Read-only: used to verify tenant exists and is active
	auditEmitter *auditEmitter
	metrics      *tenantmetrics.Metrics
}

func NewClientService(clients ClientStore, tenants TenantStore, opts ...Option) *ClientService {
	cfg := &serviceConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return &ClientService{
		clients:      clients,
		tenants:      tenants,
		auditEmitter: newAuditEmitter(cfg.logger, cfg.auditPublisher),
		metrics:      cfg.metrics,
	}
}

// CreateClient registers a client under a tenant.
// Returns the created client and the cleartext secret (only available at creation time).
func (s *ClientService) CreateClient(ctx context.Context, cmd *CreateClientCommand) (*models.Client, string, error) {
	if err := cmd.Validate(); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeValidation, "invalid client request")
	}

	tenant, err := s.tenants.FindByID(ctx, cmd.TenantID)
	if err != nil {
		return nil, "", wrapTenantErr(err, "failed to load tenant")
	}
	if !tenant.IsActive() {
		return nil, "", dErrors.New(dErrors.CodeValidation, "cannot create client under inactive tenant")
	}

	secret, secretHash, err := generateSecret(cmd.Public)
	if err != nil {
		return nil, "", err
	}

	client, err := models.NewClient(
		id.ClientID(uuid.New()),
		cmd.TenantID,
		cmd.Name,
		uuid.NewString(),
		secretHash,
		cmd.RedirectURIs,
		grantTypesToStrings(cmd.AllowedGrants),
		cmd.AllowedScopes,
		time.Now(),
	)
	if err != nil {
		return nil, "", err
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to create client")
	}

	s.auditEmitter.emit(ctx, "client.created",
		"tenant_id", client.TenantID,
		"client_id", client.ID,
		"client_name", client.Name,
	)

	return client, secret, nil
}

// GetClient returns a registered client by id.
func (s *ClientService) GetClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
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
func (s *ClientService) GetClientForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
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
func (s *ClientService) UpdateClient(ctx context.Context, clientID id.ClientID, cmd *UpdateClientCommand) (*models.Client, string, error) {
	if clientID.IsNil() {
		return nil, "", dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, "", wrapClientErr(err, "failed to get client")
	}
	return s.applyClientUpdate(ctx, client, cmd)
}

// UpdateClientForTenant enforces tenant scoping when updating a client.
// Returns the updated client and the rotated secret (empty if not rotated).
func (s *ClientService) UpdateClientForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, cmd *UpdateClientCommand) (*models.Client, string, error) {
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
	return s.applyClientUpdate(ctx, client, cmd)
}

// DeactivateClient transitions a client to inactive status.
// Returns the updated client or an error if client is not found or already inactive.
func (s *ClientService) DeactivateClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	if clientID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, wrapClientErr(err, "failed to get client")
	}

	if err := client.Deactivate(time.Now()); err != nil {
		if dErrors.HasCode(err, dErrors.CodeInvariantViolation) {
			return nil, dErrors.New(dErrors.CodeConflict, "client is already inactive")
		}
		return nil, err
	}

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update client")
	}

	s.auditEmitter.emit(ctx, "client.deactivated",
		"client_id", client.ID,
		"tenant_id", client.TenantID)

	return client, nil
}

// ReactivateClient transitions a client to active status.
// Returns the updated client or an error if client is not found or already active.
func (s *ClientService) ReactivateClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	if clientID.IsNil() {
		return nil, dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, wrapClientErr(err, "failed to get client")
	}

	if err := client.Reactivate(time.Now()); err != nil {
		if dErrors.HasCode(err, dErrors.CodeInvariantViolation) {
			return nil, dErrors.New(dErrors.CodeConflict, "client is already active")
		}
		return nil, err
	}

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update client")
	}

	s.auditEmitter.emit(ctx, "client.reactivated",
		"client_id", client.ID,
		"tenant_id", client.TenantID)

	return client, nil
}

// RotateClientSecret generates a new secret for a confidential client.
// Returns the updated client and the new cleartext secret.
// Returns an error if the client is public (has no secret to rotate).
func (s *ClientService) RotateClientSecret(ctx context.Context, clientID id.ClientID) (*models.Client, string, error) {
	if clientID.IsNil() {
		return nil, "", dErrors.New(dErrors.CodeBadRequest, "client ID required")
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, "", wrapClientErr(err, "failed to get client")
	}
	return s.rotateSecret(ctx, client)
}

// RotateClientSecretForTenant enforces tenant scoping when rotating a client secret.
func (s *ClientService) RotateClientSecretForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, string, error) {
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
	return s.rotateSecret(ctx, client)
}

// ResolveClient maps client_id -> client and tenant as a single choke point.
func (s *ClientService) ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error) {
	start := time.Now()
	defer s.observeResolveClient(start)

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
	if !tenant.IsActive() {
		return nil, nil, dErrors.New(dErrors.CodeInvalidClient, "tenant is inactive")
	}
	return client, tenant, nil
}

// rotateSecret contains the shared secret rotation logic.
func (s *ClientService) rotateSecret(ctx context.Context, client *models.Client) (*models.Client, string, error) {
	if !client.IsConfidential() {
		return nil, "", dErrors.New(dErrors.CodeValidation, "cannot rotate secret for public client")
	}

	secret, hash, err := generateSecret(false)
	if err != nil {
		return nil, "", err
	}

	client.ClientSecretHash = hash
	client.UpdatedAt = time.Now()

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to update client")
	}

	s.auditEmitter.emit(ctx, "client.secret_rotated",
		"tenant_id", client.TenantID,
		"client_id", client.ID,
	)

	return client, secret, nil
}

// applyClientUpdate contains the shared update logic for client modifications.
func (s *ClientService) applyClientUpdate(ctx context.Context, client *models.Client, cmd *UpdateClientCommand) (*models.Client, string, error) {
	if err := cmd.Validate(); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeValidation, "invalid update request")
	}

	// Apply secret rotation BEFORE grant validation so that confidentiality
	// checks reflect the post-rotation state. This prevents a public client
	// from gaining client_credentials by combining RotateSecret with grant update.
	rotatedSecret, err := s.maybeRotateSecret(client, cmd.RotateSecret)
	if err != nil {
		return nil, "", err
	}

	if err := validateGrantChanges(client, cmd); err != nil {
		return nil, "", err
	}

	applyFieldUpdates(client, cmd)

	client.UpdatedAt = time.Now()
	if err := s.clients.Update(ctx, client); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeInternal, "failed to update client")
	}

	if cmd.RotateSecret {
		s.auditEmitter.emit(ctx, "client.secret_rotated",
			"tenant_id", client.TenantID,
			"client_id", client.ID,
		)
	}

	return client, rotatedSecret, nil
}

// maybeRotateSecret generates and applies a new secret if requested.
// Returns the cleartext secret (empty if not rotated).
func (s *ClientService) maybeRotateSecret(client *models.Client, rotate bool) (string, error) {
	if !rotate {
		return "", nil
	}
	secret, hash, err := generateSecret(false)
	if err != nil {
		return "", err
	}
	client.ClientSecretHash = hash
	return secret, nil
}

// validateGrantChanges ensures requested grants are compatible with client confidentiality.
func validateGrantChanges(client *models.Client, cmd *UpdateClientCommand) error {
	if !cmd.HasAllowedGrants() {
		return nil
	}
	for _, grant := range cmd.AllowedGrants {
		if !client.CanUseGrant(grant.String()) {
			return dErrors.New(dErrors.CodeValidation, "client_credentials grant requires a confidential client")
		}
	}
	return nil
}

// applyFieldUpdates mutates client fields based on command values.
func applyFieldUpdates(client *models.Client, cmd *UpdateClientCommand) {
	if cmd.Name != nil {
		client.Name = strings.TrimSpace(*cmd.Name)
	}
	if cmd.HasRedirectURIs() {
		client.RedirectURIs = cmd.RedirectURIs
	}
	if cmd.HasAllowedGrants() {
		client.AllowedGrants = grantTypesToStrings(cmd.AllowedGrants)
	}
	if cmd.HasAllowedScopes() {
		client.AllowedScopes = cmd.AllowedScopes
	}
}

func (s *ClientService) observeResolveClient(start time.Time) {
	if s.metrics != nil {
		s.metrics.ObserveResolveClient(start)
	}
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

// grantTypesToStrings converts typed grant types to strings for storage.
func grantTypesToStrings(grants []models.GrantType) []string {
	result := make([]string, len(grants))
	for i, g := range grants {
		result[i] = g.String()
	}
	return result
}
