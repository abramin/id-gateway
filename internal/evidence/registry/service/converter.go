package service

import (
	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/providers"
)

// EvidenceToCitizenRecord converts generic Evidence to a CitizenRecord.
// Returns nil if the evidence is nil or not a citizen type.
func EvidenceToCitizenRecord(ev *providers.Evidence) *models.CitizenRecord {
	if ev == nil || ev.ProviderType != providers.ProviderTypeCitizen {
		return nil
	}

	return &models.CitizenRecord{
		NationalID:  getString(ev.Data, "national_id"),
		FullName:    getString(ev.Data, "full_name"),
		DateOfBirth: getString(ev.Data, "date_of_birth"),
		Address:     getString(ev.Data, "address"),
		Valid:       getBool(ev.Data, "valid"),
		CheckedAt:   ev.CheckedAt,
	}
}

// EvidenceToSanctionsRecord converts generic Evidence to a SanctionsRecord.
// Returns nil if the evidence is nil or not a sanctions type.
func EvidenceToSanctionsRecord(ev *providers.Evidence) *models.SanctionsRecord {
	if ev == nil || ev.ProviderType != providers.ProviderTypeSanctions {
		return nil
	}

	return &models.SanctionsRecord{
		NationalID: getString(ev.Data, "national_id"),
		Listed:     getBool(ev.Data, "listed"),
		Source:     getString(ev.Data, "source"),
		CheckedAt:  ev.CheckedAt,
	}
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
