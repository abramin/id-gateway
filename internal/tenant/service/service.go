package service

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// Service composes TenantService and ClientService into a unified facade.
// This maintains backward compatibility with existing handler code.
type Service struct {
	*TenantService
	*ClientService
	clients     ClientStore
	userCounter UserCounter
}

func New(tenants TenantStore, clients ClientStore, users UserCounter, opts ...Option) *Service {
	return &Service{
		TenantService: NewTenantService(tenants, opts...),
		ClientService: NewClientService(clients, tenants, opts...),
		clients:       clients,
		userCounter:   users,
	}
}

// GetTenant returns tenant details with user and client counts.
// This method composes data from multiple stores.
func (s *Service) GetTenant(ctx context.Context, tenantID id.TenantID) (*models.TenantDetails, error) {
	tenant, err := s.TenantService.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Add timeout to prevent cascade failures if count queries hang
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var clientCount, userCount int
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		clientCount, err = s.clients.CountByTenant(ctx, tenantID)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to count clients")
		}
		return nil
	})

	if s.userCounter != nil {
		g.Go(func() error {
			var err error
			userCount, err = s.userCounter.CountByTenant(ctx, tenantID)
			if err != nil {
				return dErrors.Wrap(err, dErrors.CodeInternal, "failed to count users")
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return &models.TenantDetails{
		ID:          tenant.ID,
		Name:        tenant.Name,
		Status:      tenant.Status,
		CreatedAt:   tenant.CreatedAt,
		UpdatedAt:   tenant.UpdatedAt,
		UserCount:   userCount,
		ClientCount: clientCount,
	}, nil
}
