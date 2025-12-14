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

	now := time.Now()
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{string(models.ScopeOpenID)}
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

	var user *models.User
	var authCode *models.AuthorizationCodeRecord
	var session *models.Session
	userWasCreated := false

	// Wrap user+code+session creation in transaction for atomicity
	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		firstName, lastName := email.DeriveNameFromEmail(req.Email)
		newUser, err := models.NewUser(uuid.New(), req.Email, firstName, lastName, false)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create user")
		}
		user, err = stores.Users.FindOrCreateByEmail(ctx, req.Email, newUser)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to find or create user")
		}
		userWasCreated = (user.ID == newUser.ID)

		// Generate OAuth 2.0 authorization code
		sessionID := uuid.New()
		authCode, err = models.NewAuthorizationCode(
			"authz_"+uuid.New().String(),
			sessionID,
			req.RedirectURI,
			now,
			now.Add(10*time.Minute),
		)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create authorization code")
		}

		if err := stores.Codes.Create(ctx, authCode); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to save authorization code")
		}

		session, err = models.NewSession(
			authCode.SessionID,
			user.ID,
			req.ClientID,
			scopes,
			string(models.SessionStatusPendingConsent),
			now,
			now.Add(s.SessionTTL),
			now,
		)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create session")
		}
		// Set optional device binding fields
		session.DeviceID = deviceID
		session.DeviceFingerprintHash = deviceFingerprint
		session.DeviceDisplayName = deviceDisplayName
		session.ApproximateLocation = ""

		if err := stores.Sessions.Create(ctx, session); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to save session")
		}

		return nil
	})

	if txErr != nil {
		return nil, txErr
	}

	// Emit audit events after successful transaction
	if userWasCreated {
		s.logAudit(ctx, string(audit.EventUserCreated),
			"user_id", user.ID.String(),
			"client_id", req.ClientID,
		)
		s.incrementUserCreated()
	}

	s.logAudit(ctx, string(audit.EventSessionCreated),
		"user_id", user.ID.String(),
		"session_id", session.ID.String(),
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
