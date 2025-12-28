package service

import (
	"fmt"

	"credo/internal/evidence/registry/domain/citizen"
	"credo/internal/evidence/registry/domain/sanctions"
	"credo/internal/evidence/registry/domain/shared"
	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/providers"
	id "credo/pkg/domain"
)

// EvidenceToCitizenVerification converts generic Evidence to a domain CitizenVerification aggregate.
// Returns an error if required fields fail validation.
func EvidenceToCitizenVerification(ev *providers.Evidence) (citizen.CitizenVerification, error) {
	if ev == nil {
		return citizen.CitizenVerification{}, fmt.Errorf("evidence is nil")
	}
	if ev.ProviderType != providers.ProviderTypeCitizen {
		return citizen.CitizenVerification{}, fmt.Errorf("wrong provider type: expected %s, got %s", providers.ProviderTypeCitizen, ev.ProviderType)
	}

	nationalIDStr := getString(ev.Data, "national_id")
	nationalID, err := id.ParseNationalID(nationalIDStr)
	if err != nil {
		return citizen.CitizenVerification{}, fmt.Errorf("invalid national_id: %w", err)
	}

	confidence, err := shared.New(ev.Confidence)
	if err != nil {
		return citizen.CitizenVerification{}, fmt.Errorf("invalid confidence: %w", err)
	}

	checkedAt := shared.NewCheckedAt(ev.CheckedAt)
	providerID := shared.NewProviderID(ev.ProviderID)

	details := citizen.PersonalDetails{
		FullName:    getString(ev.Data, "full_name"),
		DateOfBirth: getString(ev.Data, "date_of_birth"),
		Address:     getString(ev.Data, "address"),
	}

	return citizen.New(
		nationalID,
		details,
		getBool(ev.Data, "valid"),
		checkedAt,
		providerID,
		confidence,
	), nil
}

// EvidenceToSanctionsCheck converts generic Evidence to a domain SanctionsCheck aggregate.
// Returns an error if required fields fail validation.
func EvidenceToSanctionsCheck(ev *providers.Evidence) (sanctions.SanctionsCheck, error) {
	if ev == nil {
		return sanctions.SanctionsCheck{}, fmt.Errorf("evidence is nil")
	}
	if ev.ProviderType != providers.ProviderTypeSanctions {
		return sanctions.SanctionsCheck{}, fmt.Errorf("wrong provider type: expected %s, got %s", providers.ProviderTypeSanctions, ev.ProviderType)
	}

	nationalIDStr := getString(ev.Data, "national_id")
	nationalID, err := id.ParseNationalID(nationalIDStr)
	if err != nil {
		return sanctions.SanctionsCheck{}, fmt.Errorf("invalid national_id: %w", err)
	}

	confidence, err := shared.New(ev.Confidence)
	if err != nil {
		return sanctions.SanctionsCheck{}, fmt.Errorf("invalid confidence: %w", err)
	}

	checkedAt := shared.NewCheckedAt(ev.CheckedAt)
	providerID := shared.NewProviderID(ev.ProviderID)
	source := sanctions.NewSource(getString(ev.Data, "source"))

	listed := getBool(ev.Data, "listed")
	if listed {
		return sanctions.NewListedSanctionsCheck(
			nationalID,
			sanctions.ListTypeSanctions,
			"",
			"",
			source,
			checkedAt,
			providerID,
			confidence,
		), nil
	}

	return sanctions.NewSanctionsCheck(
		nationalID,
		source,
		checkedAt,
		providerID,
		confidence,
	), nil
}

// CitizenVerificationToRecord converts a domain CitizenVerification to an infrastructure CitizenRecord.
// This is the outbound conversion for persistence and transport.
func CitizenVerificationToRecord(cv citizen.CitizenVerification) *models.CitizenRecord {
	return &models.CitizenRecord{
		NationalID:  cv.NationalID().String(),
		FullName:    cv.FullName(),
		DateOfBirth: cv.DateOfBirth(),
		Address:     cv.Address(),
		Valid:       cv.IsValid(),
		Source:      cv.ProviderID().String(),
		CheckedAt:   cv.CheckedAt().Time(),
	}
}

// SanctionsCheckToRecord converts a domain SanctionsCheck to an infrastructure SanctionsRecord.
// This is the outbound conversion for persistence and transport.
func SanctionsCheckToRecord(sc sanctions.SanctionsCheck) *models.SanctionsRecord {
	return &models.SanctionsRecord{
		NationalID: sc.NationalID().String(),
		Listed:     sc.IsListed(),
		Source:     sc.Source().String(),
		CheckedAt:  sc.CheckedAt().Time(),
	}
}

// EvidenceToCitizenRecord converts generic Evidence to a CitizenRecord via domain aggregate.
// This is a convenience function that chains Evidence → Domain → Infrastructure.
// Returns an error if conversion fails.
func EvidenceToCitizenRecord(ev *providers.Evidence) (*models.CitizenRecord, error) {
	verification, err := EvidenceToCitizenVerification(ev)
	if err != nil {
		return nil, err
	}
	return CitizenVerificationToRecord(verification), nil
}

// EvidenceToSanctionsRecord converts generic Evidence to a SanctionsRecord via domain aggregate.
// This is a convenience function that chains Evidence → Domain → Infrastructure.
// Returns an error if conversion fails.
func EvidenceToSanctionsRecord(ev *providers.Evidence) (*models.SanctionsRecord, error) {
	check, err := EvidenceToSanctionsCheck(ev)
	if err != nil {
		return nil, err
	}
	return SanctionsCheckToRecord(check), nil
}

func getString(data map[string]interface{}, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}

func getBool(data map[string]interface{}, key string) bool {
	if v, ok := data[key].(bool); ok {
		return v
	}
	return false
}
