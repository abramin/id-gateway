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
	"credo/internal/auth/types"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/requestcontext"
)

type authorizeParams struct {
	Email             string
	Scopes            []string
	RedirectURI       string
	Now               time.Time
	DeviceID          string
	DeviceFingerprint string
	DeviceDisplayName string
	Client            *types.ResolvedClient
	Tenant            *types.ResolvedTenant
}

type authorizeResult struct {
	User           *models.User
	Session        *models.Session
	AuthCode       *models.AuthorizationCodeRecord
	UserWasCreated bool
}

// Authorize starts an authorization flow for a user and client.
// It validates input, resolves client and tenant, creates user/session/code,
// and emits audit signals before returning the auth code payload.
func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
	start := time.Now()
	defer func() {
		s.observeAuthorizeDuration(float64(time.Since(start).Milliseconds()))
	}()

	if req == nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "request is required")
	}

	req.Normalize()
	if err := req.Validate(); err != nil {
		return nil, err
	}

	parsedURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, dErrors.New(dErrors.CodeBadRequest, "invalid redirect_uri")
	}
	if !s.isRedirectSchemeAllowed(parsedURI) {
		return nil, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("redirect_uri scheme '%s' not allowed", parsedURI.Scheme))
	}

	// Resolve client before transaction
	client, tnt, err := s.clientResolver.ResolveClient(ctx, req.ClientID)
	if err != nil {
		if dErrors.HasCode(err, dErrors.CodeNotFound) {
			return nil, dErrors.New(dErrors.CodeBadRequest, "invalid client_id")
		}
		return nil, dErrors.Wrap(err, dErrors.CodeBadRequest, "failed to resolve client")
	}

	if !allowedRedirectURI(parsedURI.String(), client.RedirectURIs) {
		return nil, dErrors.New(dErrors.CodeBadRequest, "redirect_uri not allowed for client")
	}

	deviceID, deviceIDToSet := s.resolveDeviceID(ctx)

	params := authorizeParams{
		Email:             req.Email,
		Scopes:            req.Scopes,
		RedirectURI:       req.RedirectURI,
		Now:               requestcontext.Now(ctx),
		DeviceID:          deviceID,
		DeviceFingerprint: requestcontext.DeviceFingerprint(ctx),
		DeviceDisplayName: device.ParseUserAgent(requestcontext.UserAgent(ctx)),
		Client:            client,
		Tenant:            tnt,
	}

	if err := validateRequestedScopes(params.Scopes, client.AllowedScopes); err != nil {
		return nil, err
	}

	result, err := s.authorizeInTx(ctx, params)
	if err != nil {
		return nil, err
	}

	s.emitAuthorizeAuditEvents(ctx, result, req.ClientID)
	return s.buildAuthorizeResponse(parsedURI, result.AuthCode, req.State, deviceIDToSet), nil
}

func allowedRedirectURI(redirectURI string, clientRedirectURIs []string) bool {
	if redirectURI == "" || len(clientRedirectURIs) == 0 {
		return false
	}
	return slices.Contains(clientRedirectURIs, redirectURI)
}

// resolveDeviceID extracts or generates a device ID for session tracking.
// Returns (deviceID for session, deviceID to set in cookie).
func (s *Service) resolveDeviceID(ctx context.Context) (string, string) {
	deviceID := requestcontext.DeviceID(ctx)
	if deviceID != "" {
		return deviceID, ""
	}
	newDeviceID := s.deviceService.GenerateDeviceID()
	return newDeviceID, newDeviceID
}

func (s *Service) authorizeInTx(ctx context.Context, params authorizeParams) (*authorizeResult, error) {
	var result authorizeResult

	txErr := s.tx.RunInTx(ctx, func(stores txAuthStores) error {
		// Step 1: Find or create user
		user, wasCreated, err := s.findOrCreateUser(ctx, stores.Users, params.Tenant.ID, params.Email)
		if err != nil {
			return err
		}
		result.User = user
		result.UserWasCreated = wasCreated

		// Step 2: Create session (pending consent)
		// Note: Session must be created before auth code due to FK constraint
		sessionID := id.SessionID(uuid.New())
		session, err := models.NewSession(
			sessionID,
			user.ID,
			params.Client.ID,
			params.Tenant.ID,
			params.Scopes,
			models.SessionStatusPendingConsent,
			params.Now,
			params.Now.Add(s.SessionTTL),
			params.Now,
		)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create session")
		}

		// Step 3: Attach device binding signals
		session.SetDeviceBinding(models.DeviceBinding{
			DeviceID:            params.DeviceID,
			FingerprintHash:     params.DeviceFingerprint,
			DisplayName:         params.DeviceDisplayName,
			ApproximateLocation: "",
		})

		if err := stores.Sessions.Create(ctx, session); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to save session")
		}
		result.Session = session

		// Step 4: Generate authorization code (after session exists for FK)
		authCode, err := models.NewAuthorizationCode(
			uuid.New(),
			uuid.New().String(),
			sessionID,
			params.RedirectURI,
			params.Now,
			params.Now.Add(10*time.Minute),
			params.Now,
		)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create authorization code")
		}
		if err := stores.Codes.Create(ctx, authCode); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to save authorization code")
		}
		result.AuthCode = authCode

		return nil
	})

	if txErr != nil {
		return nil, txErr
	}
	return &result, nil
}

func (s *Service) findOrCreateUser(ctx context.Context, users UserStore, tenantID id.TenantID, userEmail string) (*models.User, bool, error) {
	firstName, lastName := email.DeriveNameFromEmail(userEmail)
	newUser, err := models.NewUser(id.UserID(uuid.New()), tenantID, userEmail, firstName, lastName, false)
	if err != nil {
		return nil, false, dErrors.Wrap(err, dErrors.CodeInternal, "failed to create user")
	}

	user, err := users.FindOrCreateByTenantAndEmail(ctx, tenantID, userEmail, newUser)
	if err != nil {
		return nil, false, dErrors.Wrap(err, dErrors.CodeInternal, "failed to find or create user")
	}
	if !user.IsActive() {
		return nil, false, dErrors.New(dErrors.CodeForbidden, "user is inactive")
	}

	wasCreated := user.ID == newUser.ID
	return user, wasCreated, nil
}

func (s *Service) emitAuthorizeAuditEvents(ctx context.Context, result *authorizeResult, clientID string) {
	if result.UserWasCreated {
		s.logAudit(ctx, string(audit.EventUserCreated),
			"user_id", result.User.ID.String(),
			"client_id", clientID,
		)
		s.incrementUserCreated()
	}

	s.logAudit(ctx, string(audit.EventSessionCreated),
		"user_id", result.User.ID.String(),
		"session_id", result.Session.ID.String(),
		"client_id", clientID,
	)
	s.incrementActiveSession()
}

func (s *Service) buildAuthorizeResponse(parsedURI *url.URL, authCode *models.AuthorizationCodeRecord, state string, deviceIDToSet string) *models.AuthorizationResult {
	query := parsedURI.Query()
	query.Set("code", authCode.Code)
	if state != "" {
		query.Set("state", state)
	}
	parsedURI.RawQuery = query.Encode()

	return &models.AuthorizationResult{
		Code:        authCode.Code,
		RedirectURI: parsedURI.String(),
		DeviceID:    deviceIDToSet,
	}
}

// validateRequestedScopes checks that all requested scopes are allowed by the client.
// Returns nil if allowed is empty (no restrictions) or all requested scopes are in allowed.
func validateRequestedScopes(requested, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("requested scope '%s' not allowed for client", scope))
		}
	}
	return nil
}
