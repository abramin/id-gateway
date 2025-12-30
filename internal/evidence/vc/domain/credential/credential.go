// Package credential defines the Credential subdomain within the VC bounded context.
//
// The Credential subdomain handles verifiable credential issuance and verification.
// It is responsible for:
//   - Creating credentials with validated claims
//   - Managing credential lifecycle and state
//   - Providing minimization capabilities for regulated environments
//
// Domain Purity: This package contains only pure domain logic with no I/O,
// no context.Context, and no time.Now() calls.
//
// Aggregate: Credential is the aggregate root, protecting the invariants
// around credential data and its minimization state.
package credential

import (
	"errors"

	"credo/internal/evidence/vc/domain/shared"
	"credo/internal/evidence/vc/models"
	id "credo/pkg/domain"
)

var (
	errMissingCredentialID = errors.New("credential_id is required")
	errMissingSubject      = errors.New("subject is required")
	errMissingIssuer       = errors.New("issuer is required")
	errMissingIssuedAt     = errors.New("issued_at is required")
	errNilClaims           = errors.New("claims cannot be nil")
)

// Credential is the aggregate root for verifiable credentials.
//
// This aggregate encapsulates:
//   - The credential identifier
//   - Credential type
//   - Subject (user who the credential is about)
//   - Issuer (entity that issued the credential)
//   - Issuance timestamp
//   - Claims (assertions)
//
// Invariants:
//   - ID is always present and valid
//   - Subject is always present and valid
//   - Issuer is always present
//   - IssuedAt is always set
//   - Claims is never nil
//   - Minimized credentials have PII stripped from claims
type Credential struct {
	id        models.CredentialID
	credType  models.CredentialType
	subject   id.UserID
	issuer    string
	issuedAt  shared.IssuedAt
	claims    ClaimSet
	minimized bool
}

// New creates a new credential with validated invariants.
// This is the only way to construct a valid Credential.
func New(
	credentialID models.CredentialID,
	credType models.CredentialType,
	subject id.UserID,
	issuer string,
	issuedAt shared.IssuedAt,
	claims ClaimSet,
) (*Credential, error) {
	if credentialID == "" {
		return nil, errMissingCredentialID
	}
	if subject.IsNil() {
		return nil, errMissingSubject
	}
	if issuer == "" {
		return nil, errMissingIssuer
	}
	if issuedAt.IsZero() {
		return nil, errMissingIssuedAt
	}
	if claims == nil {
		return nil, errNilClaims
	}

	return &Credential{
		id:        credentialID,
		credType:  credType,
		subject:   subject,
		issuer:    issuer,
		issuedAt:  issuedAt,
		claims:    claims,
		minimized: false,
	}, nil
}

// ID returns the credential ID.
func (c *Credential) ID() models.CredentialID {
	return c.id
}

// Type returns the credential type.
func (c *Credential) Type() models.CredentialType {
	return c.credType
}

// Subject returns the user ID of the credential subject.
func (c *Credential) Subject() id.UserID {
	return c.subject
}

// Issuer returns the issuer name.
func (c *Credential) Issuer() string {
	return c.issuer
}

// IssuedAt returns the issuance timestamp.
func (c *Credential) IssuedAt() shared.IssuedAt {
	return c.issuedAt
}

// Claims returns the credential claims.
func (c *Credential) Claims() ClaimSet {
	return c.claims
}

// IsMinimized returns true if this credential has PII stripped.
func (c *Credential) IsMinimized() bool {
	return c.minimized
}

// Minimized returns a new Credential with PII stripped from claims.
// This is the GDPR-compliant representation for regulated environments.
//
// The returned value:
//   - Retains: ID, Type, Subject, Issuer, IssuedAt
//   - Strips: PII from claims (delegated to ClaimSet.Minimized)
//   - Is marked as minimized (IsMinimized returns true)
//
// This method is pure - it returns a new value without modifying the original.
func (c *Credential) Minimized() *Credential {
	return &Credential{
		id:        c.id,
		credType:  c.credType,
		subject:   c.subject,
		issuer:    c.issuer,
		issuedAt:  c.issuedAt,
		claims:    c.claims.Minimized(),
		minimized: true,
	}
}
