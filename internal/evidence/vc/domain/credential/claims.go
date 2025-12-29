package credential

// ClaimSet is the interface that all credential claim types must implement.
// This provides type safety while allowing different credential types to have
// different claim structures.
type ClaimSet interface {
	// Minimized returns a copy with PII/sensitive fields removed for regulated mode.
	Minimized() ClaimSet
	// ToMap converts to an untyped map for serialization.
	ToMap() map[string]any
}

// AgeOver18Claims contains the claims for an AgeOver18 credential.
// This is a value object - immutable once constructed.
type AgeOver18Claims struct {
	isOver18    bool
	verifiedVia string
}

// NewAgeOver18Claims creates a new AgeOver18Claims value object.
func NewAgeOver18Claims(isOver18 bool, verifiedVia string) AgeOver18Claims {
	return AgeOver18Claims{
		isOver18:    isOver18,
		verifiedVia: verifiedVia,
	}
}

// IsOver18 returns the age verification result.
func (c AgeOver18Claims) IsOver18() bool {
	return c.isOver18
}

// VerifiedVia returns the verification source (empty if minimized).
func (c AgeOver18Claims) VerifiedVia() string {
	return c.verifiedVia
}

// Minimized returns a copy with PII stripped for regulated mode.
// Strips: verified_via
func (c AgeOver18Claims) Minimized() ClaimSet {
	return AgeOver18Claims{
		isOver18:    c.isOver18,
		verifiedVia: "", // stripped in regulated mode
	}
}

// ToMap converts to an untyped map for serialization.
func (c AgeOver18Claims) ToMap() map[string]any {
	m := map[string]any{
		"is_over_18": c.isOver18,
	}
	if c.verifiedVia != "" {
		m["verified_via"] = c.verifiedVia
	}
	return m
}

// AgeOver18ClaimsFromMap reconstructs AgeOver18Claims from an untyped map.
// Used when loading credentials from persistence.
func AgeOver18ClaimsFromMap(m map[string]any) AgeOver18Claims {
	isOver18, _ := m["is_over_18"].(bool)
	verifiedVia, _ := m["verified_via"].(string)
	return AgeOver18Claims{
		isOver18:    isOver18,
		verifiedVia: verifiedVia,
	}
}
