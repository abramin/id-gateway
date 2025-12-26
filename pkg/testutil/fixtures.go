package testutil

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	authmodels "credo/internal/auth/models"
	consentmodels "credo/internal/consent/models"
	tenantmodels "credo/internal/tenant/models"
	id "credo/pkg/domain"
)

// TestIDs provides convenient pre-generated IDs for tests.
// Use these for deterministic test data.
var TestIDs = struct {
	UserID1    id.UserID
	UserID2    id.UserID
	TenantID1  id.TenantID
	TenantID2  id.TenantID
	ClientID1  id.ClientID
	ClientID2  id.ClientID
	SessionID1 id.SessionID
	SessionID2 id.SessionID
}{
	UserID1:    id.UserID(uuid.MustParse("11111111-1111-1111-1111-111111111111")),
	UserID2:    id.UserID(uuid.MustParse("22222222-2222-2222-2222-222222222222")),
	TenantID1:  id.TenantID(uuid.MustParse("aaaa0000-0000-0000-0000-000000000001")),
	TenantID2:  id.TenantID(uuid.MustParse("aaaa0000-0000-0000-0000-000000000002")),
	ClientID1:  id.ClientID(uuid.MustParse("cccc0000-0000-0000-0000-000000000001")),
	ClientID2:  id.ClientID(uuid.MustParse("cccc0000-0000-0000-0000-000000000002")),
	SessionID1: id.SessionID(uuid.MustParse("eeee0000-0000-0000-0000-000000000001")),
	SessionID2: id.SessionID(uuid.MustParse("eeee0000-0000-0000-0000-000000000002")),
}

// UserBuilder provides a fluent interface for building test users.
type UserBuilder struct {
	user *authmodels.User
}

// NewUserBuilder creates a new UserBuilder with sensible defaults.
func NewUserBuilder() *UserBuilder {
	return &UserBuilder{
		user: &authmodels.User{
			ID:        id.UserID(uuid.New()),
			TenantID:  TestIDs.TenantID1,
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			Verified:  true,
			Status:    authmodels.UserStatusActive,
		},
	}
}

func (b *UserBuilder) WithID(userID id.UserID) *UserBuilder {
	b.user.ID = userID
	return b
}

func (b *UserBuilder) WithTenantID(tenantID id.TenantID) *UserBuilder {
	b.user.TenantID = tenantID
	return b
}

func (b *UserBuilder) WithEmail(email string) *UserBuilder {
	b.user.Email = email
	return b
}

func (b *UserBuilder) WithName(firstName, lastName string) *UserBuilder {
	b.user.FirstName = firstName
	b.user.LastName = lastName
	return b
}

func (b *UserBuilder) Verified(verified bool) *UserBuilder {
	b.user.Verified = verified
	return b
}

func (b *UserBuilder) WithStatus(status authmodels.UserStatus) *UserBuilder {
	b.user.Status = status
	return b
}

func (b *UserBuilder) Build() *authmodels.User {
	return b.user
}

// SessionBuilder provides a fluent interface for building test sessions.
type SessionBuilder struct {
	session *authmodels.Session
}

// NewSessionBuilder creates a new SessionBuilder with sensible defaults.
func NewSessionBuilder() *SessionBuilder {
	now := time.Now()
	return &SessionBuilder{
		session: &authmodels.Session{
			ID:             id.SessionID(uuid.New()),
			UserID:         TestIDs.UserID1,
			ClientID:       TestIDs.ClientID1,
			TenantID:       TestIDs.TenantID1,
			RequestedScope: []string{"openid"},
			Status:         authmodels.SessionStatusActive,
			CreatedAt:      now,
			ExpiresAt:      now.Add(30 * 24 * time.Hour),
			LastSeenAt:     now,
		},
	}
}

func (b *SessionBuilder) WithID(sessionID id.SessionID) *SessionBuilder {
	b.session.ID = sessionID
	return b
}

func (b *SessionBuilder) WithUserID(userID id.UserID) *SessionBuilder {
	b.session.UserID = userID
	return b
}

func (b *SessionBuilder) WithClientID(clientID id.ClientID) *SessionBuilder {
	b.session.ClientID = clientID
	return b
}

func (b *SessionBuilder) WithTenantID(tenantID id.TenantID) *SessionBuilder {
	b.session.TenantID = tenantID
	return b
}

func (b *SessionBuilder) WithScopes(scopes ...string) *SessionBuilder {
	b.session.RequestedScope = scopes
	return b
}

func (b *SessionBuilder) WithStatus(status authmodels.SessionStatus) *SessionBuilder {
	b.session.Status = status
	return b
}

func (b *SessionBuilder) WithDeviceID(deviceID string) *SessionBuilder {
	b.session.DeviceID = deviceID
	return b
}

func (b *SessionBuilder) ExpiresAt(t time.Time) *SessionBuilder {
	b.session.ExpiresAt = t
	return b
}

func (b *SessionBuilder) Revoked() *SessionBuilder {
	now := time.Now()
	b.session.Status = authmodels.SessionStatusRevoked
	b.session.RevokedAt = &now
	return b
}

func (b *SessionBuilder) Build() *authmodels.Session {
	return b.session
}

// TenantBuilder provides a fluent interface for building test tenants.
type TenantBuilder struct {
	tenant *tenantmodels.Tenant
}

// NewTenantBuilder creates a new TenantBuilder with sensible defaults.
func NewTenantBuilder() *TenantBuilder {
	return &TenantBuilder{
		tenant: &tenantmodels.Tenant{
			ID:        id.TenantID(uuid.New()),
			Name:      "Test Tenant",
			Status:    tenantmodels.TenantStatusActive,
			CreatedAt: time.Now(),
		},
	}
}

func (b *TenantBuilder) WithID(tenantID id.TenantID) *TenantBuilder {
	b.tenant.ID = tenantID
	return b
}

func (b *TenantBuilder) WithName(name string) *TenantBuilder {
	b.tenant.Name = name
	return b
}

func (b *TenantBuilder) WithStatus(status tenantmodels.TenantStatus) *TenantBuilder {
	b.tenant.Status = status
	return b
}

func (b *TenantBuilder) Build() *tenantmodels.Tenant {
	return b.tenant
}

// ClientBuilder provides a fluent interface for building test OAuth clients.
type ClientBuilder struct {
	client *tenantmodels.Client
}

// NewClientBuilder creates a new ClientBuilder with sensible defaults.
func NewClientBuilder() *ClientBuilder {
	now := time.Now()
	return &ClientBuilder{
		client: &tenantmodels.Client{
			ID:            id.ClientID(uuid.New()),
			TenantID:      TestIDs.TenantID1,
			Name:          "Test Client",
			OAuthClientID: "test-client-id",
			RedirectURIs:  []string{"https://example.com/callback"},
			AllowedGrants: []string{"authorization_code"},
			AllowedScopes: []string{"openid", "profile"},
			Status:        tenantmodels.ClientStatusActive,
			CreatedAt:     now,
			UpdatedAt:     now,
		},
	}
}

func (b *ClientBuilder) WithID(clientID id.ClientID) *ClientBuilder {
	b.client.ID = clientID
	return b
}

func (b *ClientBuilder) WithTenantID(tenantID id.TenantID) *ClientBuilder {
	b.client.TenantID = tenantID
	return b
}

func (b *ClientBuilder) WithName(name string) *ClientBuilder {
	b.client.Name = name
	return b
}

func (b *ClientBuilder) WithOAuthClientID(oauthClientID string) *ClientBuilder {
	b.client.OAuthClientID = oauthClientID
	return b
}

func (b *ClientBuilder) WithSecret(secretHash string) *ClientBuilder {
	b.client.ClientSecretHash = secretHash
	return b
}

func (b *ClientBuilder) WithRedirectURIs(uris ...string) *ClientBuilder {
	b.client.RedirectURIs = uris
	return b
}

func (b *ClientBuilder) WithGrants(grants ...string) *ClientBuilder {
	b.client.AllowedGrants = grants
	return b
}

func (b *ClientBuilder) WithScopes(scopes ...string) *ClientBuilder {
	b.client.AllowedScopes = scopes
	return b
}

func (b *ClientBuilder) WithStatus(status tenantmodels.ClientStatus) *ClientBuilder {
	b.client.Status = status
	return b
}

func (b *ClientBuilder) Build() *tenantmodels.Client {
	return b.client
}

// Quick helper functions for simple test cases

// NewTestUser creates a test user with the given ID and tenant.
func NewTestUser(userID id.UserID, tenantID id.TenantID) *authmodels.User {
	return NewUserBuilder().
		WithID(userID).
		WithTenantID(tenantID).
		Build()
}

// NewTestSession creates a test session with the given IDs.
func NewTestSession(sessionID id.SessionID, userID id.UserID, clientID id.ClientID, tenantID id.TenantID) *authmodels.Session {
	return NewSessionBuilder().
		WithID(sessionID).
		WithUserID(userID).
		WithClientID(clientID).
		WithTenantID(tenantID).
		Build()
}

// NewTestTenant creates a test tenant with the given ID and name.
func NewTestTenant(tenantID id.TenantID, name string) *tenantmodels.Tenant {
	return NewTenantBuilder().
		WithID(tenantID).
		WithName(name).
		Build()
}

// NewTestClient creates a test OAuth client with the given IDs.
func NewTestClient(clientID id.ClientID, tenantID id.TenantID) *tenantmodels.Client {
	return NewClientBuilder().
		WithID(clientID).
		WithTenantID(tenantID).
		Build()
}

// MustParsePurpose creates a consent Purpose or panics. For tests only.
func MustParsePurpose(s string) consentmodels.Purpose {
	p, err := consentmodels.ParsePurpose(s)
	if err != nil {
		panic(fmt.Sprintf("MustParsePurpose: %v", err))
	}
	return p
}
