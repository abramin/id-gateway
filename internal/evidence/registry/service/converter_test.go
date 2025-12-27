package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/domain/sanctions"
	"credo/internal/evidence/registry/domain/shared"
	"credo/internal/evidence/registry/providers"
	id "credo/pkg/domain"
)

type ConverterSuite struct {
	suite.Suite
}

func TestConverterSuite(t *testing.T) {
	suite.Run(t, new(ConverterSuite))
}

// =============================================================================
// EvidenceToSanctionsCheck Tests
// =============================================================================

// TestEvidenceToSanctionsCheck verifies converter safety and correctness.
func (s *ConverterSuite) TestEvidenceToSanctionsCheck() {
	s.Run("nil evidence returns zero value", func() {
		// Invariant: nil evidence must return zero value, not panic.
		check := EvidenceToSanctionsCheck(nil)
		s.False(check.IsListed())
		s.True(check.Source().IsZero())
	})

	s.Run("wrong provider type returns zero value", func() {
		// Invariant: wrong provider type must return zero value, not incorrect data.
		citizenEvidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"valid":       true,
			},
			CheckedAt: time.Now(),
		}

		check := EvidenceToSanctionsCheck(citizenEvidence)
		s.False(check.IsListed())
		s.True(check.Source().IsZero())
	})

	s.Run("converts unlisted evidence correctly", func() {
		checkedAt := time.Date(2025, 12, 11, 10, 0, 0, 0, time.UTC)
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"listed":      false,
				"source":      "OFAC-SDN",
			},
			CheckedAt: checkedAt,
		}

		check := EvidenceToSanctionsCheck(evidence)
		s.False(check.IsListed())
		s.Equal("OFAC-SDN", check.Source().String())
		s.Equal("123456789012", check.NationalID().String())
		s.Equal(checkedAt, check.CheckedAt().Time())
	})

	s.Run("converts listed evidence with default ListTypeSanctions", func() {
		// Invariant: Listed evidence uses NewListedSanctionsCheck with default ListTypeSanctions.
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"listed":      true,
				"source":      "OFAC-SDN",
			},
			CheckedAt: time.Now(),
		}

		check := EvidenceToSanctionsCheck(evidence)
		s.True(check.IsListed())
		s.True(check.IsSanctioned(), "default to ListTypeSanctions")
		s.False(check.IsPEP())
		s.False(check.IsOnWatchlist())
		s.True(check.RequiresEnhancedDueDiligence())
	})
}

// TestEvidenceToSanctionsCheck_InvalidNationalID verifies graceful degradation.
// Invariant: invalid national ID produces zero NationalID, not error.
func (s *ConverterSuite) TestEvidenceToSanctionsCheck_InvalidNationalID() {
	s.Run("empty string produces zero NationalID", func() {
		evidence := s.sanctionsEvidence("", false, "OFAC-SDN")
		check := EvidenceToSanctionsCheck(evidence)
		s.Equal("", check.NationalID().String())
		s.Equal("OFAC-SDN", check.Source().String())
	})

	s.Run("too short produces zero NationalID", func() {
		evidence := s.sanctionsEvidence("12345", false, "OFAC-SDN")
		check := EvidenceToSanctionsCheck(evidence)
		s.Equal("", check.NationalID().String())
	})

	s.Run("invalid chars produces zero NationalID", func() {
		evidence := s.sanctionsEvidence("ABC@#$12345", false, "OFAC-SDN")
		check := EvidenceToSanctionsCheck(evidence)
		s.Equal("", check.NationalID().String())
	})

	s.Run("nil value produces zero NationalID", func() {
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": nil,
				"listed":      false,
				"source":      "OFAC-SDN",
			},
			CheckedAt: time.Now(),
		}
		check := EvidenceToSanctionsCheck(evidence)
		s.Equal("", check.NationalID().String())
	})

	s.Run("wrong type (int) produces zero NationalID", func() {
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": 123456789012,
				"listed":      false,
				"source":      "OFAC-SDN",
			},
			CheckedAt: time.Now(),
		}
		check := EvidenceToSanctionsCheck(evidence)
		s.Equal("", check.NationalID().String())
	})
}

// TestEvidenceToSanctionsCheck_MissingFields verifies missing data handling.
func (s *ConverterSuite) TestEvidenceToSanctionsCheck_MissingFields() {
	evidence := &providers.Evidence{
		ProviderID:   "sanctions-provider",
		ProviderType: providers.ProviderTypeSanctions,
		Confidence:   1.0,
		Data:         map[string]interface{}{},
		CheckedAt:    time.Now(),
	}

	check := EvidenceToSanctionsCheck(evidence)
	s.False(check.IsListed(), "missing listed defaults to false")
	s.True(check.Source().IsZero(), "missing source is zero")
}

// =============================================================================
// SanctionsCheckToRecord Tests
// =============================================================================

// TestSanctionsCheckToRecord verifies record mapping.
// Invariant: all fields correctly transferred from domain to infrastructure.
func (s *ConverterSuite) TestSanctionsCheckToRecord() {
	nationalID := s.mustParseNationalID("123456789012")
	source := sanctions.NewSource("OFAC-SDN")
	checkedAt := shared.NewCheckedAt(time.Date(2025, 12, 11, 10, 0, 0, 0, time.UTC))
	providerID := shared.NewProviderID("test-provider")
	confidence := shared.MustConfidence(1.0)

	s.Run("unlisted check", func() {
		check := sanctions.NewSanctionsCheck(nationalID, source, checkedAt, providerID, confidence)
		record := SanctionsCheckToRecord(check)

		s.Require().NotNil(record)
		s.Equal("123456789012", record.NationalID)
		s.False(record.Listed)
		s.Equal("OFAC-SDN", record.Source)
		s.Equal(checkedAt.Time(), record.CheckedAt)
	})

	s.Run("listed check", func() {
		check := sanctions.NewListedSanctionsCheck(
			nationalID,
			sanctions.ListTypeSanctions,
			"terrorism financing",
			"2024-01-01",
			source,
			checkedAt,
			providerID,
			confidence,
		)
		record := SanctionsCheckToRecord(check)

		s.Require().NotNil(record)
		s.Equal("123456789012", record.NationalID)
		s.True(record.Listed)
		s.Equal("OFAC-SDN", record.Source)
	})
}

// =============================================================================
// EvidenceToSanctionsRecord Tests
// =============================================================================

// TestEvidenceToSanctionsRecord verifies chained conversion.
func (s *ConverterSuite) TestEvidenceToSanctionsRecord() {
	s.Run("nil evidence returns nil", func() {
		// Invariant: nil evidence must return nil, not panic.
		record := EvidenceToSanctionsRecord(nil)
		s.Nil(record)
	})

	s.Run("wrong type returns nil", func() {
		citizenEvidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   1.0,
			Data:         map[string]interface{}{},
			CheckedAt:    time.Now(),
		}
		record := EvidenceToSanctionsRecord(citizenEvidence)
		s.Nil(record, "wrong provider type returns nil")
	})

	s.Run("valid evidence converts correctly", func() {
		checkedAt := time.Date(2025, 12, 11, 10, 0, 0, 0, time.UTC)
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"listed":      true,
				"source":      "EU-SANCTIONS",
			},
			CheckedAt: checkedAt,
		}

		record := EvidenceToSanctionsRecord(evidence)
		s.Require().NotNil(record)
		s.Equal("123456789012", record.NationalID)
		s.True(record.Listed)
		s.Equal("EU-SANCTIONS", record.Source)
		s.Equal(checkedAt, record.CheckedAt)
	})
}

// =============================================================================
// Helpers
// =============================================================================

func (s *ConverterSuite) sanctionsEvidence(nationalID string, listed bool, source string) *providers.Evidence {
	return &providers.Evidence{
		ProviderID:   "sanctions-provider",
		ProviderType: providers.ProviderTypeSanctions,
		Confidence:   1.0,
		Data: map[string]interface{}{
			"national_id": nationalID,
			"listed":      listed,
			"source":      source,
		},
		CheckedAt: time.Now(),
	}
}

func (s *ConverterSuite) mustParseNationalID(str string) id.NationalID {
	nid, err := id.ParseNationalID(str)
	s.Require().NoError(err, "invalid national ID in test")
	return nid
}
