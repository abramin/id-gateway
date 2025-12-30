package credential

import (
	"errors"

	"credo/internal/evidence/vc/domain/shared"
	"credo/internal/evidence/vc/models"
)

var errUnknownCredentialType = errors.New("unknown credential type")

// ToModel converts a domain Credential to an infrastructure CredentialRecord.
// This is used when persisting credentials to the store.
func ToModel(c *Credential) models.CredentialRecord {
	return models.CredentialRecord{
		ID:       c.id,
		Type:     c.credType,
		Subject:  c.subject,
		Issuer:   c.issuer,
		IssuedAt: c.issuedAt.Time(),
		Claims:   models.Claims(c.claims.ToMap()),
	}
}

// FromModel converts an infrastructure CredentialRecord to a domain Credential.
// This is used when loading credentials from the store.
// Returns an error if the model violates domain invariants.
func FromModel(m models.CredentialRecord) (*Credential, error) {
	issuedAt, err := shared.NewIssuedAt(m.IssuedAt)
	if err != nil {
		return nil, err
	}

	// Reconstruct typed claims based on credential type
	claims, err := claimsFromMap(m.Type, m.Claims)
	if err != nil {
		return nil, err
	}

	return New(
		m.ID,
		m.Type,
		m.Subject,
		m.Issuer,
		issuedAt,
		claims,
	)
}

// claimsFromMap reconstructs typed ClaimSet from untyped map based on credential type.
// Returns an error for unknown credential types to fail fast on data corruption.
func claimsFromMap(credType models.CredentialType, m models.Claims) (ClaimSet, error) {
	switch credType {
	case models.CredentialTypeAgeOver18:
		return AgeOver18ClaimsFromMap(m), nil
	default:
		return nil, errUnknownCredentialType
	}
}
