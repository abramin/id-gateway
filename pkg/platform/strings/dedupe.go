// Package strings provides string manipulation utilities.
package strings

import (
	"strings"
)

// DedupeAndTrim removes duplicates and empty strings from a slice,
// trimming whitespace from each element. Order is preserved.
//
// Example:
//
//	DedupeAndTrim([]string{"  foo ", "bar", "foo", "", "  "})
//	// Returns: []string{"foo", "bar"}
func DedupeAndTrim(values []string) []string {
	if len(values) == 0 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			result = append(result, trimmed)
		}
	}

	return result
}

// DedupeAndTrimLower is like DedupeAndTrim but also lowercases each element.
// Useful for case-insensitive deduplication.
//
// Example:
//
//	DedupeAndTrimLower([]string{"  FOO ", "bar", "Foo"})
//	// Returns: []string{"foo", "bar"}
func DedupeAndTrimLower(values []string) []string {
	if len(values) == 0 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, v := range values {
		trimmed := strings.ToLower(strings.TrimSpace(v))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; !ok {
			seen[trimmed] = struct{}{}
			result = append(result, trimmed)
		}
	}

	return result
}

// TrimSpacePtr trims whitespace from an optional string pointer.
// Returns nil if input is nil, otherwise returns a pointer to the trimmed string.
func TrimSpacePtr(s *string) *string {
	if s == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*s)
	return &trimmed
}

// DedupeAndTrimPtr applies DedupeAndTrim to an optional slice pointer.
// Returns nil if input is nil, otherwise returns a pointer to the deduplicated slice.
func DedupeAndTrimPtr(values *[]string) *[]string {
	if values == nil {
		return nil
	}
	result := DedupeAndTrim(*values)
	return &result
}

// DedupeAndTrimLowerPtr applies DedupeAndTrimLower to an optional slice pointer.
// Returns nil if input is nil, otherwise returns a pointer to the deduplicated slice.
func DedupeAndTrimLowerPtr(values *[]string) *[]string {
	if values == nil {
		return nil
	}
	result := DedupeAndTrimLower(*values)
	return &result
}
