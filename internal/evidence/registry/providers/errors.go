package providers

import (
	"errors"
	"fmt"
)

// ErrorCategory defines the normalized failure taxonomy for provider errors.
//
// All provider implementations should use these categories to classify failures,
// allowing the orchestrator to make consistent retry and fallback decisions regardless
// of the underlying provider protocol or API.
type ErrorCategory string

const (
	// ErrorTimeout indicates the provider took too long to respond
	ErrorTimeout ErrorCategory = "timeout"

	// ErrorBadData indicates the provider returned invalid/malformed data
	ErrorBadData ErrorCategory = "bad_data"

	// ErrorAuthentication indicates credential or permission issues
	ErrorAuthentication ErrorCategory = "authentication"

	// ErrorProviderOutage indicates the provider is unavailable
	ErrorProviderOutage ErrorCategory = "provider_outage"

	// ErrorContractMismatch indicates the provider API version changed
	ErrorContractMismatch ErrorCategory = "contract_mismatch"

	// ErrorNotFound indicates the requested record doesn't exist
	ErrorNotFound ErrorCategory = "not_found"

	// ErrorRateLimited indicates too many requests
	ErrorRateLimited ErrorCategory = "rate_limited"

	// ErrorInternal indicates an unexpected internal error
	ErrorInternal ErrorCategory = "internal"
)

// ProviderError wraps provider failures with normalized categorization.
//
// This structured error type allows the orchestrator and service layers to make
// informed decisions about retries, fallbacks, and error translation without
// inspecting raw error messages or coupling to specific provider implementations.
type ProviderError struct {
	Category   ErrorCategory
	ProviderID string
	Message    string
	Underlying error
	Retryable  bool // Automatically set based on Category (timeout, outage, rate-limited → true)
}

// Error implements the error interface
func (e *ProviderError) Error() string {
	if e.Underlying != nil {
		return fmt.Sprintf("provider %s [%s]: %s: %v", e.ProviderID, e.Category, e.Message, e.Underlying)
	}
	return fmt.Sprintf("provider %s [%s]: %s", e.ProviderID, e.Category, e.Message)
}

// Unwrap supports error unwrapping
func (e *ProviderError) Unwrap() error {
	return e.Underlying
}

// NewProviderError creates a new normalized provider error with automatic retry classification.
//
// The Retryable flag is automatically set to true for transient failures (timeout, outage, rate-limited)
// and false for permanent failures (bad data, not found, auth, contract mismatch). Provider adapters
// should use this constructor to ensure consistent error handling across all implementations.
func NewProviderError(category ErrorCategory, providerID, message string, underlying error) *ProviderError {
	retryable := category == ErrorTimeout ||
		category == ErrorProviderOutage ||
		category == ErrorRateLimited

	return &ProviderError{
		Category:   category,
		ProviderID: providerID,
		Message:    message,
		Underlying: underlying,
		Retryable:  retryable,
	}
}

// IsRetryable checks if an error is worth retrying
func IsRetryable(err error) bool {
	var pe *ProviderError
	if errors.As(err, &pe) {
		return pe.Retryable
	}
	return false
}

// GetCategory extracts the error category from an error
func GetCategory(err error) ErrorCategory {
	var pe *ProviderError
	if errors.As(err, &pe) {
		return pe.Category
	}
	return ErrorInternal
}

// Sentinel errors for orchestrator-level failures.
// These are distinct from ProviderError which wraps individual provider failures.
// Use errors.Is() to check for these conditions.
var (
	ErrProviderNotFound     = errors.New("provider not found")                   // Requested provider ID not in registry
	ErrNoProvidersAvailable = errors.New("no providers available for this type") // No providers registered for requested type
	ErrAllProvidersFailed   = errors.New("all providers failed")                 // All providers in chain failed (after retries)
)
