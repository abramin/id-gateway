package correlation

import (
	"fmt"
	"maps"
	"strings"

	"credo/internal/evidence/registry/providers"
)

// CitizenNameRuleConfig configures field names for citizen conflict detection.
// This allows customizing which fields are checked when reconciling multiple citizen sources.
type CitizenNameRuleConfig struct {
	FullNameField    string // Field name for full name (default: "full_name")
	DateOfBirthField string // Field name for date of birth (default: "date_of_birth")
}

// CitizenNameRule reconciles conflicting citizen data from multiple sources.
// When evidence from multiple citizen registries disagrees (e.g., different name spellings),
// this rule selects the evidence with the highest confidence score as the authoritative source.
// Conflicts are tracked in the merged evidence's Metadata["conflicts"] field.
type CitizenNameRule struct {
	config CitizenNameRuleConfig
}

// NewCitizenNameRule creates a CitizenNameRule with configurable field names.
// Empty field names in cfg default to "full_name" and "date_of_birth" respectively.
func NewCitizenNameRule(cfg CitizenNameRuleConfig) *CitizenNameRule {
	if cfg.FullNameField == "" {
		cfg.FullNameField = "full_name"
	}
	if cfg.DateOfBirthField == "" {
		cfg.DateOfBirthField = "date_of_birth"
	}
	return &CitizenNameRule{config: cfg}
}

// Applicable returns true when there are multiple citizen-type evidence sources to reconcile.
// This rule is designed specifically for citizen registry conflicts and does not apply
// to sanctions or other provider types.
func (r *CitizenNameRule) Applicable(types []providers.ProviderType) bool {
	count := 0
	for _, t := range types {
		if t == providers.ProviderTypeCitizen {
			count++
		}
	}
	return count > 1 // Only applies when multiple citizen sources
}

// Merge combines multiple citizen evidence records into a single authoritative record.
//
// Algorithm:
//  1. Filters input to only citizen-type evidence
//  2. Selects the evidence with the highest confidence score as the base
//  3. Copies all data fields from the highest-confidence source
//  4. Detects conflicts where sources disagree on full_name or date_of_birth
//  5. Records conflict information in the returned evidence's Metadata
//
// The returned Evidence has:
//   - ProviderID: "correlation:citizen_name" to indicate synthetic origin
//   - Confidence: the confidence of the selected best source
//   - Metadata["merge_strategy"]: "highest_confidence"
//   - Metadata["sources_count"]: number of sources merged
//   - Metadata["conflicts"]: comma-separated list of conflicting fields (if any)
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
		Data:         make(map[string]any),
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

// WeightedAverageRule combines confidence scores from multiple evidence sources
// using configurable weights per provider type. This is useful when some providers
// are considered more authoritative than others (e.g., government sources vs. commercial).
//
// Provider types without explicit weights default to 1.0.
type WeightedAverageRule struct {
	Weights map[providers.ProviderType]float64
}

// Applicable returns true when there are multiple evidence sources of any type.
// Unlike CitizenNameRule, this rule is generic and can merge any combination of provider types.
func (r *WeightedAverageRule) Applicable(types []providers.ProviderType) bool {
	return len(types) > 1 // Applies to any multi-source scenario
}

// Merge combines multiple evidence records using a weighted average of confidence scores.
//
// Algorithm:
//  1. For each evidence, looks up weight by ProviderType (defaults to 1.0 if not configured)
//  2. Calculates weighted average: sum(confidence * weight) / sum(weights)
//  3. Merges data fields from all sources (later sources override earlier ones)
//
// The returned Evidence has:
//   - ProviderID: "correlation:weighted_average"
//   - ProviderType: taken from the first evidence record
//   - Confidence: the calculated weighted average
//   - Data: merged from all sources with last-write-wins semantics
//   - Metadata["merge_strategy"]: "weighted_average"
//   - Metadata["sources_count"]: number of sources merged
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
		Data:         make(map[string]any),
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
