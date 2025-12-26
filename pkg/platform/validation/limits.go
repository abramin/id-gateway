package validation

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
