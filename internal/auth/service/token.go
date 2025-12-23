package service

import (
	"context"

	"credo/internal/auth/models"
	tenant "credo/internal/tenant/models"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	if req == nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	req.Normalize()
	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch req.GrantType {
	case string(models.GrantAuthorizationCode):
		return s.exchangeAuthorizationCode(ctx, req)
	case string(models.GrantRefreshToken):
		return s.refreshWithRefreshToken(ctx, req)
	default:
		return nil, dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}
}

func (s *Service) resolveTokenContext(
	ctx context.Context,
	session *models.Session,
	clientID string,
) (*tokenContext, error) {

	client, tenant, err := s.clientResolver.ResolveClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.ID != session.ClientID {
		return nil, dErrors.New(dErrors.CodeInvalidGrant, "client mismatch")
	}
	if tenant.ID != session.TenantID {
		return nil, dErrors.New(dErrors.CodeInvalidGrant, "tenant mismatch")
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, dErrors.New(dErrors.CodeForbidden, "user inactive")
	}

	return &tokenContext{
		Session: session,
		Client:  client,
		Tenant:  tenant,
		User:    user,
	}, nil
}

type tokenContext struct {
	Session *models.Session
	Client  *tenant.Client
	Tenant  *tenant.Tenant
	User    *models.User
}

// prepareTokenFlow validates the session context and generates token artifacts.
// This is shared between authorization code exchange and refresh token flows.
// It consolidates: resolveTokenContext + client active check + generateTokenArtifacts.
func (s *Service) prepareTokenFlow(
	ctx context.Context,
	session *models.Session,
	clientID string,
	sessionIDPtr *string,
	flow TokenFlow,
) (*tokenContext, *tokenArtifacts, error) {
	tc, err := s.resolveTokenContext(ctx, session, clientID)
	if err != nil {
		return nil, nil, s.handleTokenError(ctx, err, clientID, sessionIDPtr, flow)
	}

	if !tc.Client.IsActive() {
		return nil, nil, dErrors.New(dErrors.CodeForbidden, "client is not active")
	}

	// Generate tokens BEFORE entering transaction to avoid holding mutex during JWT generation
	artifacts, err := s.generateTokenArtifacts(ctx, session)
	if err != nil {
		return nil, nil, s.handleTokenError(ctx, dErrors.Wrap(err, dErrors.CodeInternal, "failed to generate tokens"), clientID, sessionIDPtr, flow)
	}

	return tc, artifacts, nil
}
