package correlation

import (
	"fmt"
	"maps"
	"strings"

	"credo/internal/evidence/registry/providers"
)

// CitizenNameRuleConfig configures field names for citizen conflict detection
type CitizenNameRuleConfig struct {
	FullNameField    string // Field name for full name (default: "full_name")
	DateOfBirthField string // Field name for date of birth (default: "date_of_birth")
}

// CitizenNameRule reconciles conflicting names from multiple citizen sources
type CitizenNameRule struct {
	config CitizenNameRuleConfig
}

// NewCitizenNameRule creates a CitizenNameRule with configurable field names
func NewCitizenNameRule(cfg CitizenNameRuleConfig) *CitizenNameRule {
	if cfg.FullNameField == "" {
		cfg.FullNameField = "full_name"
	}
	if cfg.DateOfBirthField == "" {
		cfg.DateOfBirthField = "date_of_birth"
	}
	return &CitizenNameRule{config: cfg}
}

// Applicable checks if this rule applies
func (r *CitizenNameRule) Applicable(types []providers.ProviderType) bool {
	count := 0
	for _, t := range types {
		if t == providers.ProviderTypeCitizen {
			count++
		}
	}
	return count > 1 // Only applies when multiple citizen sources
}

// Merge combines citizen evidence by selecting highest confidence name
func (r *CitizenNameRule) Merge(evidence []*providers.Evidence) (*providers.Evidence, error) {
	if len(evidence) == 0 {
		return nil, fmt.Errorf("no evidence to merge")
	}

	// Filter to only citizen evidence
	citizenEvidence := make([]*providers.Evidence, 0)
	for _, e := range evidence {
		if e.ProviderType == providers.ProviderTypeCitizen {
			citizenEvidence = append(citizenEvidence, e)
		}
	}

	if len(citizenEvidence) == 0 {
		return nil, fmt.Errorf("no citizen evidence found")
	}

	// Find highest confidence evidence
	best := citizenEvidence[0]
	for _, e := range citizenEvidence[1:] {
		if e.Confidence > best.Confidence {
			best = e
		}
	}

	// Create merged evidence with reconciled data
	merged := &providers.Evidence{
		ProviderID:   "correlation:citizen_name",
		ProviderType: providers.ProviderTypeCitizen,
		Confidence:   best.Confidence,
		Data:         make(map[string]interface{}),
		CheckedAt:    best.CheckedAt,
		Metadata: map[string]string{
			"merge_strategy": "highest_confidence",
			"sources_count":  fmt.Sprintf("%d", len(citizenEvidence)),
		},
	}

	// Copy data from best evidence
	maps.Copy(merged.Data, best.Data)

	// Add conflict markers for differing fields
	conflicts := r.detectConflicts(citizenEvidence)
	if len(conflicts) > 0 {
		merged.Metadata["conflicts"] = strings.Join(conflicts, ",")
	}

	return merged, nil
}

// detectConflicts finds fields where evidence disagrees
func (r *CitizenNameRule) detectConflicts(evidence []*providers.Evidence) []string {
	conflicts := make([]string, 0)

	if len(evidence) < 2 {
		return conflicts
	}

	// Check full_name conflicts
	names := make(map[string]bool)
	for _, e := range evidence {
		if name, ok := e.Data[r.config.FullNameField].(string); ok {
			names[name] = true
		}
	}
	if len(names) > 1 {
		conflicts = append(conflicts, r.config.FullNameField)
	}

	// Check date_of_birth conflicts
	dobs := make(map[string]bool)
	for _, e := range evidence {
		if dob, ok := e.Data[r.config.DateOfBirthField].(string); ok {
			dobs[dob] = true
		}
	}
	if len(dobs) > 1 {
		conflicts = append(conflicts, r.config.DateOfBirthField)
	}

	return conflicts
}

// WeightedAverageRule combines confidence scores from multiple sources
type WeightedAverageRule struct {
	Weights map[providers.ProviderType]float64
}

// Applicable checks if this rule applies
func (r *WeightedAverageRule) Applicable(types []providers.ProviderType) bool {
	return len(types) > 1 // Applies to any multi-source scenario
}

// Merge combines evidence using weighted confidence scores
func (r *WeightedAverageRule) Merge(evidence []*providers.Evidence) (*providers.Evidence, error) {
	if len(evidence) == 0 {
		return nil, fmt.Errorf("no evidence to merge")
	}

	// Calculate weighted confidence
	var totalWeight float64
	var weightedSum float64

	for _, e := range evidence {
		weight := r.Weights[e.ProviderType]
		if weight == 0 {
			weight = 1.0 // Default weight
		}
		totalWeight += weight
		weightedSum += e.Confidence * weight
	}

	avgConfidence := weightedSum / totalWeight

	// Create merged evidence
	merged := &providers.Evidence{
		ProviderID:   "correlation:weighted_average",
		ProviderType: evidence[0].ProviderType, // Use first type as representative
		Confidence:   avgConfidence,
		Data:         make(map[string]interface{}),
		CheckedAt:    evidence[0].CheckedAt,
		Metadata: map[string]string{
			"merge_strategy": "weighted_average",
			"sources_count":  fmt.Sprintf("%d", len(evidence)),
		},
	}

	// Merge data fields (later sources override earlier)
	for _, e := range evidence {
		maps.Copy(merged.Data, e.Data)
	}

	return merged, nil
}
