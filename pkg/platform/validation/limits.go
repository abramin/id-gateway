package validation

import (
	"fmt"

	dErrors "credo/pkg/domain-errors"
)

// HTTP body limits
const (
	// MaxBodySize is the maximum allowed request body size (64 KB).
	// Sufficient for JSON APIs while preventing memory exhaustion attacks.
	MaxBodySize = 64 * 1024
)

// Slice element count limits
const (
	// MaxScopes is the maximum number of OAuth scopes per request.
	MaxScopes = 20

	// MaxRedirectURIs is the maximum number of redirect URIs per client.
	MaxRedirectURIs = 10

	// MaxPurposes is the maximum number of consent purposes per request.
	MaxPurposes = 50

	// MaxGrants is the maximum number of OAuth grant types per client.
	MaxGrants = 10
)

// String element length limits
const (
	// MaxScopeLength is the maximum length of an individual scope string.
	MaxScopeLength = 100

	// MaxRedirectURILength is the maximum length of a redirect URI.
	MaxRedirectURILength = 2048

	// MaxPurposeIDLength is the maximum length of a purpose identifier.
	MaxPurposeIDLength = 100

	// MaxEmailLength is the maximum length of an email address.
	MaxEmailLength = 255

	// MaxClientIDLength is the maximum length of a client ID.
	MaxClientIDLength = 100

	// MaxStateLength is the maximum length of an OAuth state parameter.
	MaxStateLength = 500

	// MaxCodeLength is the maximum length of an authorization code.
	MaxCodeLength = 256

	// MaxRefreshTokenLength is the maximum length of a refresh token.
	MaxRefreshTokenLength = 256
)

// CheckSliceCount validates that a slice does not exceed the maximum count.
func CheckSliceCount(fieldName string, count, max int) error {
	if count > max {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("too many %s: max %d allowed", fieldName, max))
	}
	return nil
}

// CheckStringLength validates that a string does not exceed the maximum length.
func CheckStringLength(fieldName, value string, max int) error {
	if len(value) > max {
		return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("%s exceeds max length of %d", fieldName, max))
	}
	return nil
}

// CheckEachStringLength validates that each string in a slice does not exceed the maximum length.
func CheckEachStringLength(fieldName string, values []string, max int) error {
	for _, v := range values {
		if len(v) > max {
			return dErrors.New(dErrors.CodeValidation, fmt.Sprintf("%s exceeds max length of %d", fieldName, max))
		}
	}
	return nil
}
