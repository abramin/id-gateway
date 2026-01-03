package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	tenantmetrics "credo/internal/tenant/metrics"
	"credo/internal/tenant/models"
	"credo/internal/tenant/secrets"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/sentinel"
	"credo/pkg/requestcontext"
)

// ClientService orchestrates client registration and lifecycle management.
type ClientService struct {
	clients      ClientStore
	tenants      TenantStore // Read-only: used to verify tenant exists and is active
	auditEmitter *auditEmitter
	metrics      *tenantmetrics.Metrics
	tx           StoreTx
}

func NewClientService(clients ClientStore, tenants TenantStore, opts ...Option) *ClientService {
	cfg := &serviceConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	tx := cfg.tx
	if tx == nil {
		tx = newInMemoryStoreTx()
	}
	return &ClientService{
		clients:      clients,
		tenants:      tenants,
		auditEmitter: newAuditEmitter(cfg.logger, cfg.auditPublisher),
		metrics:      cfg.metrics,
		tx:           tx,
	}
}

// CreateClient registers a client under a tenant.
// Returns the created client and the cleartext secret (only available at creation time).
func (s *ClientService) CreateClient(ctx context.Context, cmd *CreateClientCommand) (*models.Client, string, error) {
	start := time.Now()
	defer s.observeCreateClient(start)

	if err := cmd.Validate(); err != nil {
		return nil, "", dErrors.Wrap(err, dErrors.CodeValidation, "invalid client request")
	}

	var client *models.Client
	var secret string
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		tenant, err := s.tenants.FindByID(txCtx, cmd.TenantID)
		if err != nil {
			return wrapTenantErr(err)
		}
		if !tenant.IsActive() {
			return dErrors.New(dErrors.CodeValidation, "cannot create client under inactive tenant")
		}

		secretValue, secretHash, err := generateSecret(cmd.Public)
		if err != nil {
			return err
		}

		newClient, err := models.NewClient(
			id.ClientID(uuid.New()),
			cmd.TenantID,
			cmd.Name,
			uuid.NewString(),
			secretHash,
			cmd.RedirectURIs,
			cmd.AllowedGrants,
			cmd.AllowedScopes,
			requestcontext.Now(txCtx),
		)
		if err != nil {
			return err
		}

		if err := s.clients.Create(txCtx, newClient); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create client")
		}

		if err := s.auditEmitter.emitClientCreated(txCtx, models.ClientCreated{
			TenantID:   newClient.TenantID,
			ClientID:   newClient.ID,
			ClientName: newClient.Name,
		}); err != nil {
			return err
		}

		client = newClient
		secret = secretValue
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	return client, secret, nil
}

// GetClient returns a registered client by id.
func (s *ClientService) GetClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}
	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		return nil, wrapClientErr(err, "failed to get client")
	}
	return client, nil
}

// GetClientForTenant enforces tenant scoping when retrieving a client.
func (s *ClientService) GetClientForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, error) {
	if err := requireTenantID(tenantID); err != nil {
		return nil, err
	}
	if err := requireClientID(clientID); err != nil {
		return nil, err
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
	if err := requireClientID(clientID); err != nil {
		return nil, "", err
	}
	var updated *models.Client
	var secret string
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		client, err := s.clients.FindByID(txCtx, clientID)
		if err != nil {
			return wrapClientErr(err, "failed to get client")
		}
		updated, secret, err = s.applyClientUpdate(txCtx, client, cmd)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return updated, secret, nil
}

// UpdateClientForTenant enforces tenant scoping when updating a client.
// Returns the updated client and the rotated secret (empty if not rotated).
func (s *ClientService) UpdateClientForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID, cmd *UpdateClientCommand) (*models.Client, string, error) {
	if err := requireTenantID(tenantID); err != nil {
		return nil, "", err
	}
	if err := requireClientID(clientID); err != nil {
		return nil, "", err
	}
	var updated *models.Client
	var secret string
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		client, err := s.clients.FindByTenantAndID(txCtx, tenantID, clientID)
		if err != nil {
			return wrapClientErr(err, "failed to get client")
		}
		updated, secret, err = s.applyClientUpdate(txCtx, client, cmd)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return updated, secret, nil
}

// DeactivateClient transitions a client to inactive status.
// Returns the updated client or an error if client is not found or already inactive.
func (s *ClientService) DeactivateClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}
	var updated *models.Client
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		client, err := s.clients.FindByID(txCtx, clientID)
		if err != nil {
			return wrapClientErr(err, "failed to get client")
		}

		if err := client.Deactivate(requestcontext.Now(txCtx)); err != nil {
			if dErrors.HasCode(err, dErrors.CodeInvariantViolation) {
				return dErrors.New(dErrors.CodeConflict, "client is already inactive")
			}
			return err
		}

		if err := s.clients.Update(txCtx, client); err != nil {
			return wrapClientErr(err, "failed to update client")
		}

		if err := s.auditEmitter.emitClientDeactivated(txCtx, models.ClientDeactivated{
			TenantID: client.TenantID,
			ClientID: client.ID,
		}); err != nil {
			return err
		}

		updated = client
		return nil
	})
	if err != nil {
		return nil, err
	}

	return updated, nil
}

// ReactivateClient transitions a client to active status.
// Returns the updated client or an error if client is not found or already active.
func (s *ClientService) ReactivateClient(ctx context.Context, clientID id.ClientID) (*models.Client, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}
	var updated *models.Client
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		client, err := s.clients.FindByID(txCtx, clientID)
		if err != nil {
			return wrapClientErr(err, "failed to get client")
		}

		if err := client.Reactivate(requestcontext.Now(txCtx)); err != nil {
			if dErrors.HasCode(err, dErrors.CodeInvariantViolation) {
				return dErrors.New(dErrors.CodeConflict, "client is already active")
			}
			return err
		}

		if err := s.clients.Update(txCtx, client); err != nil {
			return wrapClientErr(err, "failed to update client")
		}

		if err := s.auditEmitter.emitClientReactivated(txCtx, models.ClientReactivated{
			TenantID: client.TenantID,
			ClientID: client.ID,
		}); err != nil {
			return err
		}

		updated = client
		return nil
	})
	if err != nil {
		return nil, err
	}

	return updated, nil
}

// RotateClientSecret generates a new secret for a confidential client.
// Returns the updated client and the new cleartext secret.
// Returns an error if the client is public (has no secret to rotate).
func (s *ClientService) RotateClientSecret(ctx context.Context, clientID id.ClientID) (*models.Client, string, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, "", err
	}
	var updated *models.Client
	var secret string
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		client, err := s.clients.FindByID(txCtx, clientID)
		if err != nil {
			return wrapClientErr(err, "failed to get client")
		}
		updated, secret, err = s.rotateSecret(txCtx, client)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return updated, secret, nil
}

// RotateClientSecretForTenant enforces tenant scoping when rotating a client secret.
func (s *ClientService) RotateClientSecretForTenant(ctx context.Context, tenantID id.TenantID, clientID id.ClientID) (*models.Client, string, error) {
	if err := requireTenantID(tenantID); err != nil {
		return nil, "", err
	}
	if err := requireClientID(clientID); err != nil {
		return nil, "", err
	}
	var updated *models.Client
	var secret string
	err := s.tx.RunInTx(ctx, func(txCtx context.Context) error {
		client, err := s.clients.FindByTenantAndID(txCtx, tenantID, clientID)
		if err != nil {
			return wrapClientErr(err, "failed to get client")
		}
		updated, secret, err = s.rotateSecret(txCtx, client)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return updated, secret, nil
}

// VerifyClientSecret verifies a client's credentials for authentication.
// Returns nil if the secret is valid, or an error if verification fails.
// This is the explicit entry point for auth module to verify client secrets.
//
// Security: Uses bcrypt constant-time comparison via secrets.Verify.
// Returns a generic "invalid credentials" error to prevent enumeration attacks.
func (s *ClientService) VerifyClientSecret(ctx context.Context, clientID id.ClientID, providedSecret string) error {
	if err := requireClientID(clientID); err != nil {
		return err
	}

	client, err := s.clients.FindByID(ctx, clientID)
	if err != nil {
		// Return generic error to prevent client enumeration
		return invalidClientCredentials()
	}

	// Public clients cannot authenticate with a secret
	if !client.IsConfidential() {
		return invalidClientCredentials()
	}

	// Verify the secret using bcrypt constant-time comparison
	if err := secrets.Verify(providedSecret, client.ClientSecretHash); err != nil {
		return invalidClientCredentials()
	}

	return nil
}

// VerifyClientSecretByOAuthID verifies a client's credentials using the OAuth client_id string.
// This is the common entry point used during token endpoint authentication.
//
// Security: Uses bcrypt constant-time comparison via secrets.Verify.
// Returns a generic "invalid credentials" error to prevent enumeration attacks.
func (s *ClientService) VerifyClientSecretByOAuthID(ctx context.Context, oauthClientID, providedSecret string) error {
	oauthClientID = strings.TrimSpace(oauthClientID)
	if oauthClientID == "" {
		return dErrors.New(dErrors.CodeInvalidClient, "client_id is required")
	}

	client, err := s.clients.FindByOAuthClientID(ctx, oauthClientID)
	if err != nil {
		// Return generic error to prevent client enumeration
		return invalidClientCredentials()
	}

	// Public clients cannot authenticate with a secret
	if !client.IsConfidential() {
		return invalidClientCredentials()
	}

	// Verify the secret using bcrypt constant-time comparison
	if err := secrets.Verify(providedSecret, client.ClientSecretHash); err != nil {
		return invalidClientCredentials()
	}

	return nil
}

// ResolveClient maps client_id -> client and tenant as a single choke point.
// If the client or tenant is inactive, returns an invalid_client error.
func (s *ClientService) ResolveClient(ctx context.Context, clientID string) (*models.Client, *models.Tenant, error) {
	start := time.Now()
	defer s.observeResolveClient(start)

	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, nil, dErrors.New(dErrors.CodeValidation, "client_id is required")
	}

	client, err := s.clients.FindByOAuthClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, sentinel.ErrNotFound) {
			return nil, nil, invalidClientCredentials()
		}
		return nil, nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to resolve client")
	}
	if !client.IsActive() {
		return nil, nil, invalidClientCredentials()
	}

	tenant, err := s.tenants.FindByID(ctx, client.TenantID)
	if err != nil {
		if errors.Is(err, sentinel.ErrNotFound) {
			return nil, nil, invalidClientCredentials()
		}
		return nil, nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to load tenant for client")
	}
	if !tenant.IsActive() {
		return nil, nil, invalidClientCredentials()
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
	client.UpdatedAt = requestcontext.Now(ctx)

	if err := s.clients.Update(ctx, client); err != nil {
		return nil, "", wrapClientErr(err, "failed to update client")
	}

	if err := s.auditEmitter.emitClientSecretRotated(ctx, models.ClientSecretRotated{
		TenantID: client.TenantID,
		ClientID: client.ID,
	}); err != nil {
		return nil, "", err
	}

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

	client.UpdatedAt = requestcontext.Now(ctx)
	if err := s.clients.Update(ctx, client); err != nil {
		return nil, "", wrapClientErr(err, "failed to update client")
	}

	if cmd.RotateSecret {
		if err := s.auditEmitter.emitClientSecretRotated(ctx, models.ClientSecretRotated{
			TenantID: client.TenantID,
			ClientID: client.ID,
		}); err != nil {
			return nil, "", err
		}
	}

	return client, rotatedSecret, nil
}

// maybeRotateSecret generates and applies a new secret if requested.
// Returns the cleartext secret (empty if not rotated).
// Returns an error if rotation is requested on a public client.
func (s *ClientService) maybeRotateSecret(client *models.Client, rotate bool) (string, error) {
	if !rotate {
		return "", nil
	}
	if !client.IsConfidential() {
		return "", dErrors.New(dErrors.CodeValidation, "cannot rotate secret for public client")
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
		if !client.CanUseGrant(grant) {
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
		client.AllowedGrants = cmd.AllowedGrants
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

func (s *ClientService) observeCreateClient(start time.Time) {
	if s.metrics != nil {
		s.metrics.ObserveCreateClient(start)
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

func invalidClientCredentials() error {
	return dErrors.New(dErrors.CodeInvalidClient, "invalid client credentials")
}
