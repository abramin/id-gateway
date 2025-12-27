// Package sanctions defines the Sanctions subdomain within the Registry bounded context.
//
// The Sanctions subdomain handles compliance screening against sanctions lists,
// PEP (Politically Exposed Persons) databases, and watchlists. It is responsible for:
//   - Determining if a subject is on any sanctions or watchlist
//   - Categorizing the type of listing (sanctions, PEP, watchlist)
//   - Providing the source and reason for any listing
//
// Domain Purity: This package contains only pure domain logic with no I/O,
// no context.Context, and no time.Now() calls.
//
// Aggregate: SanctionsCheck is the aggregate root, protecting the invariants
// around listing status and its metadata.
package sanctions

import (
	"credo/internal/evidence/registry/domain/shared"
	id "credo/pkg/domain"
)

// ListType categorizes the type of sanctions/watchlist entry.
type ListType string

const (
	// ListTypeNone indicates the subject is not listed.
	ListTypeNone ListType = ""

	// ListTypeSanctions indicates the subject is on a formal sanctions list
	// (e.g., UN Security Council, OFAC SDN, EU Sanctions).
	ListTypeSanctions ListType = "sanctions"

	// ListTypePEP indicates the subject is a Politically Exposed Person
	// or a family member/close associate of one.
	ListTypePEP ListType = "pep"

	// ListTypeWatchlist indicates the subject is on a monitoring watchlist
	// (e.g., enhanced due diligence required, adverse media).
	ListTypeWatchlist ListType = "watchlist"
)

func (l ListType) IsValid() bool {
	switch l {
	case ListTypeNone, ListTypeSanctions, ListTypePEP, ListTypeWatchlist:
		return true
	default:
		return false
	}
}

func (l ListType) String() string {
	return string(l)
}

// ListingDetails contains metadata about why a subject is listed.
// This is only populated when Listed is true.
type ListingDetails struct {
	ListType   ListType
	Reason     string
	ListedDate string // Format: YYYY-MM-DD, when added to list
}

// IsEmpty returns true if there are no listing details.
func (l ListingDetails) IsEmpty() bool {
	return l.ListType == ListTypeNone && l.Reason == "" && l.ListedDate == ""
}

// Source identifies where the sanctions check was performed.
type Source struct {
	value string
}

// NewSource creates a Source.
func NewSource(value string) Source {
	return Source{value: value}
}

func (s Source) String() string {
	return s.value
}

func (s Source) IsZero() bool {
	return s.value == ""
}

// SanctionsCheck is the aggregate root for sanctions/PEP screening.
//
// This aggregate encapsulates:
//   - The subject identifier (NationalID from pkg/domain)
//   - Listing status (whether the subject is on any list)
//   - Listing details (type, reason, date - only if listed)
//   - Source of the check
//   - Evidence provenance (provider, confidence, timestamp)
//
// Invariants:
//   - NationalID is always present
//   - Source is always present
//   - CheckedAt is always set
//   - If Listed is true, ListType must be set (not ListTypeNone)
//   - If Listed is false, ListingDetails should be empty
type SanctionsCheck struct {
	nationalID id.NationalID
	listed     bool
	details    ListingDetails
	source     Source
	checkedAt  shared.CheckedAt
	providerID shared.ProviderID
	confidence shared.Confidence
}

// NewSanctionsCheck creates a new sanctions check result for a non-listed subject.
func NewSanctionsCheck(
	nationalID id.NationalID,
	source Source,
	checkedAt shared.CheckedAt,
	providerID shared.ProviderID,
	confidence shared.Confidence,
) SanctionsCheck {
	return SanctionsCheck{
		nationalID: nationalID,
		listed:     false,
		details:    ListingDetails{},
		source:     source,
		checkedAt:  checkedAt,
		providerID: providerID,
		confidence: confidence,
	}
}

// NewListedSanctionsCheck creates a sanctions check result for a listed subject.
// This constructor enforces the invariant that listed subjects must have a ListType.
func NewListedSanctionsCheck(
	nationalID id.NationalID,
	listType ListType,
	reason string,
	listedDate string,
	source Source,
	checkedAt shared.CheckedAt,
	providerID shared.ProviderID,
	confidence shared.Confidence,
) SanctionsCheck {
	// Enforce invariant: listed subjects must have a list type
	if listType == ListTypeNone {
		listType = ListTypeSanctions // Default to sanctions if not specified
	}

	return SanctionsCheck{
		nationalID: nationalID,
		listed:     true,
		details: ListingDetails{
			ListType:   listType,
			Reason:     reason,
			ListedDate: listedDate,
		},
		source:     source,
		checkedAt:  checkedAt,
		providerID: providerID,
		confidence: confidence,
	}
}

func (s SanctionsCheck) NationalID() id.NationalID {
	return s.nationalID
}

func (s SanctionsCheck) IsListed() bool {
	return s.listed
}

func (s SanctionsCheck) ListType() ListType {
	return s.details.ListType
}

func (s SanctionsCheck) Reason() string {
	return s.details.Reason
}

func (s SanctionsCheck) ListedDate() string {
	return s.details.ListedDate
}

func (s SanctionsCheck) ListingDetails() ListingDetails {
	return s.details
}

func (s SanctionsCheck) Source() Source {
	return s.source
}

func (s SanctionsCheck) CheckedAt() shared.CheckedAt {
	return s.checkedAt
}

func (s SanctionsCheck) ProviderID() shared.ProviderID {
	return s.providerID
}

func (s SanctionsCheck) Confidence() shared.Confidence {
	return s.confidence
}

// IsSanctioned returns true if specifically on a sanctions list (not PEP/watchlist).
func (s SanctionsCheck) IsSanctioned() bool {
	return s.listed && s.details.ListType == ListTypeSanctions
}

// IsPEP returns true if the subject is a Politically Exposed Person.
func (s SanctionsCheck) IsPEP() bool {
	return s.listed && s.details.ListType == ListTypePEP
}

// IsOnWatchlist returns true if on a monitoring watchlist.
func (s SanctionsCheck) IsOnWatchlist() bool {
	return s.listed && s.details.ListType == ListTypeWatchlist
}

// RequiresEnhancedDueDiligence returns true if the check result requires EDD.
// This is true for any listed status (sanctions, PEP, or watchlist).
func (s SanctionsCheck) RequiresEnhancedDueDiligence() bool {
	return s.listed
}
