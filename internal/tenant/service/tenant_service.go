package service

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	tenantmetrics "credo/internal/tenant/metrics"
	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/middleware/requesttime"
	"credo/pkg/platform/sentinel"
)

// TenantService orchestrates tenant lifecycle management.
type TenantService struct {
	tenants      TenantStore
	auditEmitter *auditEmitter
	metrics      *tenantmetrics.Metrics
}

func NewTenantService(tenants TenantStore, opts ...Option) *TenantService {
	cfg := &serviceConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return &TenantService{
		tenants:      tenants,
		auditEmitter: newAuditEmitter(cfg.logger, cfg.auditPublisher),
		metrics:      cfg.metrics,
	}
}

func (s *TenantService) CreateTenant(ctx context.Context, name string) (*models.Tenant, error) {
	name = strings.TrimSpace(name)

	t, err := models.NewTenant(id.TenantID(uuid.New()), name, requesttime.Now(ctx))
	if err != nil {
		return nil, err
	}

	if err := s.tenants.CreateIfNameAvailable(ctx, t); err != nil {
		if errors.Is(err, sentinel.ErrAlreadyUsed) || dErrors.HasCode(err, dErrors.CodeConflict) {
			return nil, dErrors.New(dErrors.CodeConflict, "tenant name must be unique")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create tenant")
	}
	s.auditEmitter.emitTenantCreated(ctx, models.TenantCreated{TenantID: t.ID})
	s.incrementTenantCreated()

	return t, nil
}

func (s *TenantService) GetTenant(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error) {
	if err := requireTenantID(tenantID); err != nil {
		return nil, err
	}
	tenant, err := s.tenants.FindByID(ctx, tenantID)
	if err != nil {
		return nil, wrapTenantErr(err, "failed to load tenant")
	}
	return tenant, nil
}

// DeactivateTenant transitions a tenant to inactive status.
// Returns the updated tenant or an error if tenant is not found or already inactive.
func (s *TenantService) DeactivateTenant(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error) {
	if err := requireTenantID(tenantID); err != nil {
		return nil, err
	}
	tenant, err := s.tenants.FindByID(ctx, tenantID)
	if err != nil {
		return nil, wrapTenantErr(err, "failed to load tenant")
	}

	if err := tenant.Deactivate(requesttime.Now(ctx)); err != nil {
		if dErrors.HasCode(err, dErrors.CodeInvariantViolation) {
			return nil, dErrors.New(dErrors.CodeConflict, "tenant is already inactive")
		}
		return nil, err
	}

	if err := s.tenants.Update(ctx, tenant); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update tenant")
	}

	s.auditEmitter.emitTenantDeactivated(ctx, models.TenantDeactivated{TenantID: tenant.ID})

	return tenant, nil
}

// ReactivateTenant transitions a tenant to active status.
// Returns the updated tenant or an error if tenant is not found or already active.
func (s *TenantService) ReactivateTenant(ctx context.Context, tenantID id.TenantID) (*models.Tenant, error) {
	if err := requireTenantID(tenantID); err != nil {
		return nil, err
	}
	tenant, err := s.tenants.FindByID(ctx, tenantID)
	if err != nil {
		return nil, wrapTenantErr(err, "failed to load tenant")
	}

	if err := tenant.Reactivate(requesttime.Now(ctx)); err != nil {
		if dErrors.HasCode(err, dErrors.CodeInvariantViolation) {
			return nil, dErrors.New(dErrors.CodeConflict, "tenant is already active")
		}
		return nil, err
	}

	if err := s.tenants.Update(ctx, tenant); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to update tenant")
	}

	s.auditEmitter.emitTenantReactivated(ctx, models.TenantReactivated{TenantID: tenant.ID})

	return tenant, nil
}

func (s *TenantService) incrementTenantCreated() {
	if s.metrics != nil {
		s.metrics.IncrementTenantCreated()
	}
}
