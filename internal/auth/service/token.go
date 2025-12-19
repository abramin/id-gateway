package service

import (
	"context"
	"errors"
	"strings"

	"credo/internal/auth/models"
	"credo/internal/sentinel"
	tenant "credo/internal/tenant/models"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	if req == nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	req.Normalize()
	if err := req.Validate(); err != nil {
		code := dErrors.CodeValidation
		if errors.Is(err, sentinel.ErrBadRequest) {
			code = dErrors.CodeBadRequest
		}
		// Extract just the context message without the sentinel
		msg := strings.TrimSuffix(err.Error(), ": "+sentinel.ErrInvalidInput.Error())
		msg = strings.TrimSuffix(msg, ": "+sentinel.ErrBadRequest.Error())
		return nil, dErrors.New(code, msg)
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
