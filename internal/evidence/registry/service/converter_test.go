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

func (s *ConverterSuite) TestEvidenceToSanctionsCheck() {
	s.Run("nil evidence returns error", func() {
		_, err := EvidenceToSanctionsCheck(nil)
		s.Error(err)
		s.Contains(err.Error(), "evidence is nil")
	})

	s.Run("wrong provider type returns error", func() {
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

		_, err := EvidenceToSanctionsCheck(citizenEvidence)
		s.Error(err)
		s.Contains(err.Error(), "wrong provider type")
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

		check, err := EvidenceToSanctionsCheck(evidence)
		s.Require().NoError(err)
		s.False(check.IsListed())
		s.Equal("OFAC-SDN", check.Source().String())
		s.Equal("123456789012", check.NationalID().String())
		s.Equal(checkedAt, check.CheckedAt().Time())
	})

	s.Run("converts listed evidence with default ListTypeSanctions", func() {
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

		check, err := EvidenceToSanctionsCheck(evidence)
		s.Require().NoError(err)
		s.True(check.IsListed())
		s.True(check.IsSanctioned(), "default to ListTypeSanctions")
		s.False(check.IsPEP())
		s.False(check.IsOnWatchlist())
		s.True(check.RequiresEnhancedDueDiligence())
	})
}

// TestEvidenceToSanctionsCheck_InvalidNationalID verifies validation errors.
func (s *ConverterSuite) TestEvidenceToSanctionsCheck_InvalidNationalID() {
	s.Run("empty string returns error", func() {
		evidence := s.sanctionsEvidence("", false, "OFAC-SDN")
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})

	s.Run("too short returns error", func() {
		evidence := s.sanctionsEvidence("12345", false, "OFAC-SDN")
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})

	s.Run("invalid chars returns error", func() {
		evidence := s.sanctionsEvidence("ABC@#$12345", false, "OFAC-SDN")
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})

	s.Run("nil value returns error", func() {
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
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})

	s.Run("wrong type (int) returns error", func() {
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
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})
}

// TestEvidenceToSanctionsCheck_InvalidConfidence verifies confidence validation.
func (s *ConverterSuite) TestEvidenceToSanctionsCheck_InvalidConfidence() {
	s.Run("negative confidence returns error", func() {
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   -0.5,
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"listed":      false,
				"source":      "OFAC-SDN",
			},
			CheckedAt: time.Now(),
		}
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid confidence")
	})

	s.Run("confidence over 1.0 returns error", func() {
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.5,
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"listed":      false,
				"source":      "OFAC-SDN",
			},
			CheckedAt: time.Now(),
		}
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid confidence")
	})
}

// TestEvidenceToSanctionsCheck_MissingFields verifies missing data handling.
func (s *ConverterSuite) TestEvidenceToSanctionsCheck_MissingFields() {
	s.Run("missing national_id returns error", func() {
		evidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data:         map[string]interface{}{},
			CheckedAt:    time.Now(),
		}
		_, err := EvidenceToSanctionsCheck(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})
}

// =============================================================================
// SanctionsCheckToRecord Tests
// =============================================================================

func (s *ConverterSuite) TestSanctionsCheckToRecord() {
	nationalID := s.mustParseNationalID("123456789012")
	source := sanctions.NewSource("OFAC-SDN")
	checkedAt := shared.NewCheckedAt(time.Date(2025, 12, 11, 10, 0, 0, 0, time.UTC))
	providerID := shared.NewProviderID("test-provider")
	confidence := shared.Authoritative()

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

func (s *ConverterSuite) TestEvidenceToSanctionsRecord() {
	s.Run("nil evidence returns error", func() {
		record, err := EvidenceToSanctionsRecord(nil)
		s.Error(err)
		s.Nil(record)
	})

	s.Run("wrong type returns error", func() {
		citizenEvidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   1.0,
			Data:         map[string]interface{}{},
			CheckedAt:    time.Now(),
		}
		record, err := EvidenceToSanctionsRecord(citizenEvidence)
		s.Error(err)
		s.Nil(record)
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

		record, err := EvidenceToSanctionsRecord(evidence)
		s.Require().NoError(err)
		s.Require().NotNil(record)
		s.Equal("123456789012", record.NationalID)
		s.True(record.Listed)
		s.Equal("EU-SANCTIONS", record.Source)
		s.Equal(checkedAt, record.CheckedAt)
	})
}

// =============================================================================
// EvidenceToCitizenVerification Tests
// =============================================================================

func (s *ConverterSuite) TestEvidenceToCitizenVerification() {
	s.Run("nil evidence returns error", func() {
		_, err := EvidenceToCitizenVerification(nil)
		s.Error(err)
		s.Contains(err.Error(), "evidence is nil")
	})

	s.Run("wrong provider type returns error", func() {
		sanctionsEvidence := &providers.Evidence{
			ProviderID:   "sanctions-provider",
			ProviderType: providers.ProviderTypeSanctions,
			Confidence:   1.0,
			Data:         map[string]interface{}{},
			CheckedAt:    time.Now(),
		}

		_, err := EvidenceToCitizenVerification(sanctionsEvidence)
		s.Error(err)
		s.Contains(err.Error(), "wrong provider type")
	})

	s.Run("valid evidence converts correctly", func() {
		checkedAt := time.Date(2025, 12, 11, 10, 0, 0, 0, time.UTC)
		evidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id":   "123456789012",
				"full_name":     "John Doe",
				"date_of_birth": "1990-01-01",
				"address":       "123 Main St",
				"valid":         true,
			},
			CheckedAt: checkedAt,
		}

		verification, err := EvidenceToCitizenVerification(evidence)
		s.Require().NoError(err)
		s.Equal("123456789012", verification.NationalID().String())
		s.Equal("John Doe", verification.FullName())
		s.Equal("1990-01-01", verification.DateOfBirth())
		s.Equal("123 Main St", verification.Address())
		s.True(verification.IsValid())
		s.Equal(checkedAt, verification.CheckedAt().Time())
	})

	s.Run("invalid national_id returns error", func() {
		evidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id": "short",
				"valid":       true,
			},
			CheckedAt: time.Now(),
		}

		_, err := EvidenceToCitizenVerification(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid national_id")
	})

	s.Run("invalid confidence returns error", func() {
		evidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   2.0, // Invalid: > 1.0
			Data: map[string]interface{}{
				"national_id": "123456789012",
				"valid":       true,
			},
			CheckedAt: time.Now(),
		}

		_, err := EvidenceToCitizenVerification(evidence)
		s.Error(err)
		s.Contains(err.Error(), "invalid confidence")
	})
}

// =============================================================================
// EvidenceToCitizenRecord Tests
// =============================================================================

func (s *ConverterSuite) TestEvidenceToCitizenRecord() {
	s.Run("nil evidence returns error", func() {
		record, err := EvidenceToCitizenRecord(nil)
		s.Error(err)
		s.Nil(record)
	})

	s.Run("valid evidence converts correctly", func() {
		checkedAt := time.Date(2025, 12, 11, 10, 0, 0, 0, time.UTC)
		evidence := &providers.Evidence{
			ProviderID:   "citizen-provider",
			ProviderType: providers.ProviderTypeCitizen,
			Confidence:   1.0,
			Data: map[string]interface{}{
				"national_id":   "123456789012",
				"full_name":     "Jane Doe",
				"date_of_birth": "1985-05-15",
				"address":       "456 Oak Ave",
				"valid":         true,
			},
			CheckedAt: checkedAt,
		}

		record, err := EvidenceToCitizenRecord(evidence)
		s.Require().NoError(err)
		s.Require().NotNil(record)
		s.Equal("123456789012", record.NationalID)
		s.Equal("Jane Doe", record.FullName)
		s.Equal("1985-05-15", record.DateOfBirth)
		s.Equal("456 Oak Ave", record.Address)
		s.True(record.Valid)
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
