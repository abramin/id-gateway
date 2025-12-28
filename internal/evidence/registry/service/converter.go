package service

import (
	"fmt"

	"credo/internal/evidence/registry/domain/citizen"
	"credo/internal/evidence/registry/domain/sanctions"
	"credo/internal/evidence/registry/domain/shared"
	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/providers"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
)

// EvidenceToCitizenVerification converts generic Evidence to a domain CitizenVerification aggregate.
// Returns an error if required fields fail validation.
// Uses getRequiredString/getRequiredBool for mandatory fields to prevent silent defaults.
func EvidenceToCitizenVerification(ev *providers.Evidence) (citizen.CitizenVerification, error) {
	if ev == nil {
		return citizen.CitizenVerification{}, dErrors.New(dErrors.CodeBadRequest, "evidence is nil")
	}
	if ev.ProviderType != providers.ProviderTypeCitizen {
		return citizen.CitizenVerification{}, dErrors.New(dErrors.CodeBadRequest,
			fmt.Sprintf("wrong provider type: expected %s, got %s", providers.ProviderTypeCitizen, ev.ProviderType))
	}

	// Required field: national_id
	nationalIDStr, err := getRequiredString(ev.Data, "national_id")
	if err != nil {
		return citizen.CitizenVerification{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid provider response")
	}
	nationalID, err := id.ParseNationalID(nationalIDStr)
	if err != nil {
		return citizen.CitizenVerification{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid national_id format")
	}

	confidence, err := shared.New(ev.Confidence)
	if err != nil {
		return citizen.CitizenVerification{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid confidence value")
	}

	// Required field: valid (boolean)
	valid, err := getRequiredBool(ev.Data, "valid")
	if err != nil {
		return citizen.CitizenVerification{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid provider response")
	}

	checkedAt := shared.NewCheckedAt(ev.CheckedAt)
	providerID := shared.NewProviderID(ev.ProviderID)

	// Optional fields: personal details (may be empty in regulated mode)
	details := citizen.PersonalDetails{
		FullName:    getString(ev.Data, "full_name"),
		DateOfBirth: getString(ev.Data, "date_of_birth"),
		Address:     getString(ev.Data, "address"),
	}

	verification, err := citizen.New(
		nationalID,
		details,
		valid,
		checkedAt,
		providerID,
		confidence,
	)
	if err != nil {
		return citizen.CitizenVerification{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid citizen verification")
	}
	return verification, nil
}

// EvidenceToSanctionsCheck converts generic Evidence to a domain SanctionsCheck aggregate.
// Returns an error if required fields fail validation.
// Uses getRequiredString/getRequiredBool to prevent silent defaults on critical security fields.
func EvidenceToSanctionsCheck(ev *providers.Evidence) (sanctions.SanctionsCheck, error) {
	if ev == nil {
		return sanctions.SanctionsCheck{}, dErrors.New(dErrors.CodeBadRequest, "evidence is nil")
	}
	if ev.ProviderType != providers.ProviderTypeSanctions {
		return sanctions.SanctionsCheck{}, dErrors.New(dErrors.CodeBadRequest,
			fmt.Sprintf("wrong provider type: expected %s, got %s", providers.ProviderTypeSanctions, ev.ProviderType))
	}

	// Required field: national_id
	nationalIDStr, err := getRequiredString(ev.Data, "national_id")
	if err != nil {
		return sanctions.SanctionsCheck{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid provider response")
	}
	nationalID, err := id.ParseNationalID(nationalIDStr)
	if err != nil {
		return sanctions.SanctionsCheck{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid national_id format")
	}

	confidence, err := shared.New(ev.Confidence)
	if err != nil {
		return sanctions.SanctionsCheck{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid confidence value")
	}

	// Required field: listed (boolean) - critical for security, must not default to false
	listed, err := getRequiredBool(ev.Data, "listed")
	if err != nil {
		return sanctions.SanctionsCheck{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid provider response")
	}

	checkedAt := shared.NewCheckedAt(ev.CheckedAt)
	providerID := shared.NewProviderID(ev.ProviderID)
	source := sanctions.NewSource(getString(ev.Data, "source"))

	if listed {
		check, err := sanctions.NewListedSanctionsCheck(
			nationalID,
			sanctions.ListTypeSanctions,
			"",
			"",
			source,
			checkedAt,
			providerID,
			confidence,
		)
		if err != nil {
			return sanctions.SanctionsCheck{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid sanctions check")
		}
		return check, nil
	}

	check, err := sanctions.NewSanctionsCheck(
		nationalID,
		source,
		checkedAt,
		providerID,
		confidence,
	)
	if err != nil {
		return sanctions.SanctionsCheck{}, dErrors.Wrap(err, dErrors.CodeBadRequest, "invalid sanctions check")
	}
	return check, nil
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

// getRequiredString extracts a required string field from provider data.
// Returns an error if the field is missing or has the wrong type.
// This prevents silent defaults that could create invalid domain state.
func getRequiredString(data map[string]interface{}, key string) (string, error) {
	v, ok := data[key]
	if !ok {
		return "", dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("required field missing: %s", key))
	}
	s, ok := v.(string)
	if !ok {
		return "", dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("field %s has wrong type: expected string, got %T", key, v))
	}
	return s, nil
}

// getRequiredBool extracts a required boolean field from provider data.
// Returns an error if the field is missing or has the wrong type.
// This prevents silent defaults that could create false-negative results.
func getRequiredBool(data map[string]interface{}, key string) (bool, error) {
	v, ok := data[key]
	if !ok {
		return false, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("required field missing: %s", key))
	}
	b, ok := v.(bool)
	if !ok {
		return false, dErrors.New(dErrors.CodeBadRequest, fmt.Sprintf("field %s has wrong type: expected bool, got %T", key, v))
	}
	return b, nil
}

// getString extracts an optional string field from provider data.
// Returns empty string if missing or wrong type (for optional fields only).
func getString(data map[string]interface{}, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}
