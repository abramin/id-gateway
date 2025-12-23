package service

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"

	"credo/internal/auth/device"
	"credo/internal/auth/email"
	"credo/internal/auth/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	devicemw "credo/pkg/platform/middleware/device"
	metadata "credo/pkg/platform/middleware/metadata"
)

func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
	if req == nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	req.Normalize()
	if err := req.Validate(); err != nil {
		// Validate now returns domain-errors directly
		return nil, err
	}

	parsedURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid redirect_uri")
	}
	if !s.isRedirectSchemeAllowed(parsedURI) {
		return nil, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("redirect_uri scheme '%s' not allowed", parsedURI.Scheme))
	}

	now := time.Now()
	scopes := req.Scopes

	userAgent := metadata.GetUserAgent(ctx)
	deviceDisplayName := device.ParseUserAgent(userAgent)

	// Always generate device ID for session tracking; DeviceBindingEnabled controls enforcement only
	deviceID := devicemw.GetDeviceID(ctx)
	deviceIDToSet := ""
	if deviceID == "" {
		deviceID = s.deviceService.GenerateDeviceID()
		deviceIDToSet = deviceID
	}

	// Fingerprint is now pre-computed by Device middleware
	deviceFingerprint := devicemw.GetDeviceFingerprint(ctx)

	var user *models.User
	var authCode *models.AuthorizationCodeRecord
	var session *models.Session
	userWasCreated := false

	client, tenant, err := s.clientResolver.ResolveClient(ctx, req.ClientID)
	if err != nil {
		// RFC 6749 §4.1.2.1: invalid client_id is a bad request, not "not found"
		if dErrors.HasCode(err, dErrors.CodeNotFound) {
			return nil, dErrors.New(dErrors.CodeBadRequest, "invalid client_id")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeBadRequest, "failed to resolve client")
	}

	if req.RedirectURI != "" {
		if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
			return nil, dErrors.New(dErrors.CodeBadRequest, "redirect_uri not allowed")
		}
	}

	// Wrap user+code+session creation in transaction for atomicity
	txErr := s.tx.RunInTx(ctx, func(stores TxAuthStores) error {
		// --- Step 1: Find or create user ---
		firstName, lastName := email.DeriveNameFromEmail(req.Email)
		newUser, err := models.NewUser(id.UserID(uuid.New()), tenant.ID, req.Email, firstName, lastName, false)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create user")
		}
		user, err = stores.Users.FindOrCreateByTenantAndEmail(ctx, tenant.ID, req.Email, newUser)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to find or create user")
		}
		if !user.IsActive() {
			return dErrors.New(dErrors.CodeForbidden, "user is inactive")
		}
		userWasCreated = (user.ID == newUser.ID)

		// --- Step 2: Generate authorization code ---
		sessionID := id.SessionID(uuid.New())
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

		// --- Step 3: Create session (pending consent) ---
		session, err = models.NewSession(
			authCode.SessionID,
			user.ID,
			client.ID,
			tenant.ID,
			scopes,
			models.SessionStatusPendingConsent,
			now,
			now.Add(s.SessionTTL),
			now,
		)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create session")
		}

		// --- Step 4: Attach device binding signals ---
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
