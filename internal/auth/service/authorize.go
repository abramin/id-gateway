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
	tenant "credo/internal/tenant/models"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	devicemw "credo/pkg/platform/middleware/device"
	metadata "credo/pkg/platform/middleware/metadata"
	"credo/pkg/platform/middleware/requesttime"
)

type authorizeParams struct {
	Email             string
	Scopes            []string
	RedirectURI       string
	Now               time.Time
	DeviceID          string
	DeviceFingerprint string
	DeviceDisplayName string
	Client            *tenant.Client
	Tenant            *tenant.Tenant
}

type authorizeResult struct {
	User           *models.User
	Session        *models.Session
	AuthCode       *models.AuthorizationCodeRecord
	UserWasCreated bool
}

func (s *Service) Authorize(ctx context.Context, req *models.AuthorizationRequest) (*models.AuthorizationResult, error) {
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

	if req.RedirectURI != "" && !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return nil, dErrors.New(dErrors.CodeBadRequest, "redirect_uri not allowed")
	}

	deviceID, deviceIDToSet := s.resolveDeviceID(ctx)

	params := authorizeParams{
		Email:             req.Email,
		Scopes:            req.Scopes,
		RedirectURI:       req.RedirectURI,
		Now:               requesttime.Now(ctx),
		DeviceID:          deviceID,
		DeviceFingerprint: devicemw.GetDeviceFingerprint(ctx),
		DeviceDisplayName: device.ParseUserAgent(metadata.GetUserAgent(ctx)),
		Client:            client,
		Tenant:            tnt,
	}

	if len(client.AllowedScopes) > 0 {
		for _, scope := range params.Scopes {
			if !slices.Contains(client.AllowedScopes, scope) {
				return nil, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("requested scope '%s' not allowed for client", scope))
			}
		}
	}

	result, err := s.authorizeInTx(ctx, params)
	if err != nil {
		return nil, err
	}

	s.emitAuthorizeAuditEvents(ctx, result, req.ClientID)
	return s.buildAuthorizeResponse(parsedURI, result.AuthCode, req.State, deviceIDToSet), nil
}

// resolveDeviceID extracts or generates a device ID for session tracking.
// Returns (deviceID for session, deviceID to set in cookie).
func (s *Service) resolveDeviceID(ctx context.Context) (string, string) {
	deviceID := devicemw.GetDeviceID(ctx)
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

		// Step 2: Generate authorization code
		sessionID := id.SessionID(uuid.New())
		authCode, err := models.NewAuthorizationCode(
			uuid.New().String(),
			sessionID,
			params.RedirectURI,
			params.Now,
			params.Now.Add(10*time.Minute),
		)
		if err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to create authorization code")
		}
		if err := stores.Codes.Create(ctx, authCode); err != nil {
			return dErrors.Wrap(err, dErrors.CodeInternal, "failed to save authorization code")
		}
		result.AuthCode = authCode

		// Step 3: Create session (pending consent)
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

		// Step 4: Attach device binding signals
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
