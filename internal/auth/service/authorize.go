package service

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/device"
	"credo/internal/auth/models"
	"credo/internal/platform/middleware"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/email"
)

func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
	parsedURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid redirect_uri")
	}
	if !s.isRedirectSchemeAllowed(parsedURI) {
		return nil, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("redirect_uri scheme '%s' not allowed", parsedURI.Scheme))
	}

	firstName, lastName := email.DeriveNameFromEmail(req.Email)
	newUser := &models.User{
		ID:        uuid.New(),
		Email:     req.Email,
		FirstName: firstName,
		LastName:  lastName,
		Verified:  false,
	}
	user, err := s.users.FindOrCreateByEmail(ctx, req.Email, newUser)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find or create user")
	}
	if user.ID == newUser.ID {
		s.logAudit(ctx, string(audit.EventUserCreated),
			"user_id", user.ID.String(),
			"client_id", req.ClientID,
		)
		s.incrementUserCreated()
	}

	now := time.Now()
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{models.ScopeOpenID.String()}
	}

	// Generate OAuth 2.0 authorization code
	authCode := &models.AuthorizationCodeRecord{
		Code:        "authz_" + uuid.New().String(),
		SessionID:   uuid.New(),
		RedirectURI: req.RedirectURI,
		ExpiresAt:   now.Add(10 * time.Minute),
		Used:        false,
		CreatedAt:   now,
	}

	if err := s.codes.Create(ctx, authCode); err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to save authorization code")
	}

	userAgent := middleware.GetUserAgent(ctx)
	deviceDisplayName := device.ParseUserAgent(userAgent)

	deviceID := ""
	deviceIDToSet := ""
	if s.DeviceBindingEnabled {
		deviceID = middleware.GetDeviceID(ctx)
		if deviceID == "" {
			deviceID = s.deviceService.GenerateDeviceID()
			deviceIDToSet = deviceID
		}
	}

	deviceFingerprint := s.deviceService.ComputeFingerprint(userAgent)

	newSession := &models.Session{
		ID:                    authCode.SessionID,
		UserID:                user.ID,
		ClientID:              req.ClientID,
		RequestedScope:        scopes,
		DeviceID:              deviceID,
		DeviceFingerprintHash: deviceFingerprint,
		DeviceDisplayName:     deviceDisplayName,
		ApproximateLocation:   "",
		Status:                StatusPendingConsent,
		CreatedAt:             now,
		ExpiresAt:             now.Add(s.SessionTTL),
		LastSeenAt:            now,
	}

	err = s.sessions.Create(ctx, newSession)
	if err != nil {
		return nil, dErrors.Wrap(err, dErrors.CodeInternal, "failed to save session")
	}
	s.logAudit(ctx, string(audit.EventSessionCreated),
		"user_id", user.ID.String(),
		"session_id", newSession.ID.String(),
		"client_id", req.ClientID,
	)
	s.incrementActiveSession()

	query := parsedURI.Query()
	query.Set("code", authCode.Code) // OAuth 2.0: return authorization code, not session_id
	if req.State != "" {
		query.Set("state", req.State)
	}
	parsedURI.RawQuery = query.Encode()
	redirectURI := parsedURI.String()
	res := &models.AuthorizationResult{
		Code:        authCode.Code,
		RedirectURI: redirectURI,
		DeviceID:    deviceIDToSet,
	}

	return res, nil
}
