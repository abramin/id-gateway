package service

import (
	"context"
	"strings"

	"credo/internal/auth/models"
	dErrors "credo/pkg/domain-errors"
)

func (s *Service) Token(ctx context.Context, req *models.TokenRequest) (*models.TokenResult, error) {
	if err := s.validateTokenRequest(req); err != nil {
		return nil, err
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case GrantTypeRefreshToken:
		return s.refreshWithRefreshToken(ctx, req)
	default:
		return nil, dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}
}

func (s *Service) validateTokenRequest(req *models.TokenRequest) error {
	if req == nil {
		return dErrors.New(dErrors.CodeBadRequest, "invalid request")
	}
	if strings.TrimSpace(req.GrantType) == "" {
		return dErrors.New(dErrors.CodeValidation, "grant_type is required")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return dErrors.New(dErrors.CodeValidation, "client_id is required")
	}

	switch req.GrantType {
	case "authorization_code":
		if strings.TrimSpace(req.Code) == "" {
			return dErrors.New(dErrors.CodeValidation, "code is required")
		}
		if strings.TrimSpace(req.RedirectURI) == "" {
			return dErrors.New(dErrors.CodeValidation, "redirect_uri is required")
		}
	case "refresh_token":
		if strings.TrimSpace(req.RefreshToken) == "" {
			return dErrors.New(dErrors.CodeValidation, "refresh_token is required")
		}
	default:
		// OAuth 2.0: unsupported_grant_type
		return dErrors.New(dErrors.CodeBadRequest, "unsupported grant_type")
	}

	return nil
}
