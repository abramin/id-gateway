package sanctions

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/domain/shared"
	id "credo/pkg/domain"
)

type SanctionsDomainSuite struct {
	suite.Suite
}

func TestSanctionsDomainSuite(t *testing.T) {
	suite.Run(t, new(SanctionsDomainSuite))
}

// TestListType verifies type safety for list types.
// Invariant: Unknown list types must return false to prevent invalid state.
func (s *SanctionsDomainSuite) TestListType() {
	s.Run("valid types return true", func() {
		s.True(ListTypeNone.IsValid())
		s.True(ListTypeSanctions.IsValid())
		s.True(ListTypePEP.IsValid())
		s.True(ListTypeWatchlist.IsValid())
		s.True(ListType("").IsValid(), "empty string (None) is valid")
	})

	s.Run("unknown type returns false", func() {
		s.False(ListType("unknown").IsValid())
	})
}

// TestListingDetails verifies value object correctness for empty detection.
// Invariant: Only fully empty struct should return true.
func (s *SanctionsDomainSuite) TestListingDetails() {
	s.Run("IsEmpty returns true when all fields empty", func() {
		details := ListingDetails{}
		s.True(details.IsEmpty())
	})

	s.Run("IsEmpty returns false when ListType set", func() {
		details := ListingDetails{ListType: ListTypeSanctions}
		s.False(details.IsEmpty())
	})

	s.Run("IsEmpty returns false when Reason set", func() {
		details := ListingDetails{Reason: "some reason"}
		s.False(details.IsEmpty())
	})

	s.Run("IsEmpty returns false when ListedDate set", func() {
		details := ListingDetails{ListedDate: "2024-01-01"}
		s.False(details.IsEmpty())
	})

	s.Run("IsEmpty returns false when all fields set", func() {
		details := ListingDetails{
			ListType:   ListTypeSanctions,
			Reason:     "terrorism",
			ListedDate: "2024-01-01",
		}
		s.False(details.IsEmpty())
	})
}

// TestSource verifies value object correctness for Source.
func (s *SanctionsDomainSuite) TestSource() {
	s.Run("IsZero for empty source", func() {
		s.True(NewSource("").IsZero())
		s.True(Source{}.IsZero())
	})

	s.Run("IsZero false for populated source", func() {
		s.False(NewSource("OFAC").IsZero())
	})

	s.Run("String returns wrapped value", func() {
		source := NewSource("OFAC-SDN")
		s.Equal("OFAC-SDN", source.String())
	})
}

// TestNewSanctionsCheck verifies constructor contract for unlisted subjects.
// Invariant: Unlisted check must have listed=false and empty details.
func (s *SanctionsDomainSuite) TestNewSanctionsCheck() {
	nationalID := s.mustParseNationalID("123456789012")
	source := NewSource("test-registry")
	checkedAt := shared.NewCheckedAt(time.Now())
	providerID := shared.NewProviderID("test-provider")
	confidence := shared.Authoritative()

	check := NewSanctionsCheck(nationalID, source, checkedAt, providerID, confidence)

	s.False(check.IsListed(), "unlisted check must have listed=false")
	s.True(check.ListingDetails().IsEmpty(), "unlisted check must have empty details")
	s.Equal(ListTypeNone, check.ListType(), "unlisted check must have ListTypeNone")
	s.Equal(nationalID, check.NationalID())
	s.Equal(source, check.Source())
}

// TestNewListedSanctionsCheck verifies key invariant.
// Invariant: Listed subjects must have a ListType; ListTypeNone defaults to ListTypeSanctions.
func (s *SanctionsDomainSuite) TestNewListedSanctionsCheck() {
	nationalID := s.mustParseNationalID("123456789012")
	source := NewSource("test-registry")
	checkedAt := shared.NewCheckedAt(time.Now())
	providerID := shared.NewProviderID("test-provider")
	confidence := shared.Authoritative()

	s.Run("defaults ListTypeNone to ListTypeSanctions", func() {
		check := NewListedSanctionsCheck(
			nationalID, ListTypeNone, "test reason", "2024-01-01",
			source, checkedAt, providerID, confidence,
		)
		s.True(check.IsListed())
		s.Equal(ListTypeSanctions, check.ListType())
	})

	s.Run("preserves ListTypeSanctions", func() {
		check := NewListedSanctionsCheck(
			nationalID, ListTypeSanctions, "", "",
			source, checkedAt, providerID, confidence,
		)
		s.Equal(ListTypeSanctions, check.ListType())
	})

	s.Run("preserves ListTypePEP", func() {
		check := NewListedSanctionsCheck(
			nationalID, ListTypePEP, "", "",
			source, checkedAt, providerID, confidence,
		)
		s.Equal(ListTypePEP, check.ListType())
	})

	s.Run("preserves ListTypeWatchlist", func() {
		check := NewListedSanctionsCheck(
			nationalID, ListTypeWatchlist, "", "",
			source, checkedAt, providerID, confidence,
		)
		s.Equal(ListTypeWatchlist, check.ListType())
	})
}

// TestSanctionsCheck_QueryMethods verifies business logic for type-specific queries.
// Invariant: IsSanctioned/IsPEP/IsOnWatchlist only true for specific ListTypes.
func (s *SanctionsDomainSuite) TestSanctionsCheck_QueryMethods() {
	nationalID := s.mustParseNationalID("123456789012")
	source := NewSource("test-registry")
	checkedAt := shared.NewCheckedAt(time.Now())
	providerID := shared.NewProviderID("test-provider")
	confidence := shared.Authoritative()

	s.Run("unlisted subject returns false for all queries", func() {
		check := NewSanctionsCheck(nationalID, source, checkedAt, providerID, confidence)
		s.False(check.IsListed())
		s.False(check.IsSanctioned())
		s.False(check.IsPEP())
		s.False(check.IsOnWatchlist())
	})

	s.Run("sanctions list returns true only for IsSanctioned", func() {
		check := NewListedSanctionsCheck(nationalID, ListTypeSanctions, "", "", source, checkedAt, providerID, confidence)
		s.True(check.IsListed())
		s.True(check.IsSanctioned())
		s.False(check.IsPEP())
		s.False(check.IsOnWatchlist())
	})

	s.Run("PEP list returns true only for IsPEP", func() {
		check := NewListedSanctionsCheck(nationalID, ListTypePEP, "", "", source, checkedAt, providerID, confidence)
		s.True(check.IsListed())
		s.False(check.IsSanctioned())
		s.True(check.IsPEP())
		s.False(check.IsOnWatchlist())
	})

	s.Run("watchlist returns true only for IsOnWatchlist", func() {
		check := NewListedSanctionsCheck(nationalID, ListTypeWatchlist, "", "", source, checkedAt, providerID, confidence)
		s.True(check.IsListed())
		s.False(check.IsSanctioned())
		s.False(check.IsPEP())
		s.True(check.IsOnWatchlist())
	})
}

// TestSanctionsCheck_RequiresEnhancedDueDiligence verifies business rule.
// Invariant: Any listed status requires enhanced due diligence.
func (s *SanctionsDomainSuite) TestSanctionsCheck_RequiresEnhancedDueDiligence() {
	nationalID := s.mustParseNationalID("123456789012")
	source := NewSource("test-registry")
	checkedAt := shared.NewCheckedAt(time.Now())
	providerID := shared.NewProviderID("test-provider")
	confidence := shared.Authoritative()

	s.Run("unlisted does not require EDD", func() {
		check := NewSanctionsCheck(nationalID, source, checkedAt, providerID, confidence)
		s.False(check.RequiresEnhancedDueDiligence())
	})

	s.Run("sanctions list requires EDD", func() {
		check := NewListedSanctionsCheck(nationalID, ListTypeSanctions, "", "", source, checkedAt, providerID, confidence)
		s.True(check.RequiresEnhancedDueDiligence())
	})

	s.Run("PEP requires EDD", func() {
		check := NewListedSanctionsCheck(nationalID, ListTypePEP, "", "", source, checkedAt, providerID, confidence)
		s.True(check.RequiresEnhancedDueDiligence())
	})

	s.Run("watchlist requires EDD", func() {
		check := NewListedSanctionsCheck(nationalID, ListTypeWatchlist, "", "", source, checkedAt, providerID, confidence)
		s.True(check.RequiresEnhancedDueDiligence())
	})
}

// mustParseNationalID is a test helper that panics on invalid national ID.
func (s *SanctionsDomainSuite) mustParseNationalID(str string) id.NationalID {
	nid, err := id.ParseNationalID(str)
	s.Require().NoError(err, "invalid national ID in test")
	return nid
}
