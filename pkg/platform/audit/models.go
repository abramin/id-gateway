package audit

import (
	"time"

	id "credo/pkg/domain"
)

// EventCategory classifies audit events by their primary purpose.
// This enables different retention policies, storage backends, and routing.
type EventCategory string

const (
	// CategoryCompliance covers events with legal/regulatory significance.
	// These require tamper-proof storage and long retention (e.g., 7 years).
	// Examples: consent changes, user creation/deletion, data subject rights.
	CategoryCompliance EventCategory = "compliance"

	// CategorySecurity covers events relevant to security monitoring and forensics.
	// These feed into SIEM systems and alerting pipelines.
	// Examples: auth failures, lockouts, secret rotations, access violations.
	CategorySecurity EventCategory = "security"

	// CategoryOperations covers events useful for debugging and operational visibility.
	// These can be sampled or aggregated with shorter retention.
	// Examples: token issuance, session creation, routine access patterns.
	CategoryOperations EventCategory = "operations"
)

// Event is emitted from domain logic to capture key actions. Keep it
// transport-agnostic so stores and sinks can fan out.
type Event struct {
	Category        EventCategory
	Timestamp       time.Time
	UserID          id.UserID
	Subject         string
	Action          string
	Purpose         string
	RequestingParty string
	Decision        string
	Reason          string
	// PRD-001B: Enrichment fields for audit trail completeness
	Email     string // User email when available (e.g., during user deletion)
	RequestID string // Correlation ID from HTTP request context
	// ActorID tracks who performed the action when different from UserID.
	// Used for admin operations where an admin acts on a user's behalf.
	// This is a string to support various actor identification schemes.
	ActorID string
	// SubjectIDHash is a SHA-256 hash of the subject identifier (e.g., national ID)
	// being evaluated. Used for compliance traceability without storing raw PII.
	// Only populated for decision events where a third-party identity is evaluated.
	SubjectIDHash string
}

type AuditEvent string

const (
	// Auth events
	EventUserCreated      AuditEvent = "user_created"
	EventSessionCreated   AuditEvent = "session_created"
	EventSessionRevoked   AuditEvent = "session_revoked"
	EventSessionsRevoked  AuditEvent = "sessions_revoked"
	EventTokenIssued      AuditEvent = "token_issued"
	EventTokenRefreshed   AuditEvent = "token_refreshed"
	EventUserInfoAccessed AuditEvent = "userinfo_accessed"
	EventAuthFailed       AuditEvent = "auth_failed"
	EventUserDeleted      AuditEvent = "user_deleted"

	// Tenant events
	EventTenantCreated     AuditEvent = "tenant_created"
	EventTenantDeactivated AuditEvent = "tenant_deactivated"
	EventTenantReactivated AuditEvent = "tenant_reactivated"

	// Client events
	EventClientCreated       AuditEvent = "client_created"
	EventClientDeactivated   AuditEvent = "client_deactivated"
	EventClientReactivated   AuditEvent = "client_reactivated"
	EventClientSecretRotated AuditEvent = "client_secret_rotated"

	// Consent events
	EventConsentGranted AuditEvent = "consent_granted"
	EventConsentRevoked AuditEvent = "consent_revoked"
	EventConsentDeleted AuditEvent = "consent_deleted"
	EventConsentChecked AuditEvent = "consent_checked"

	// Rate limit events
	EventRateLimitExceeded    AuditEvent = "rate_limit_exceeded"
	EventAuthLockoutTriggered AuditEvent = "auth_lockout_triggered"
	EventAuthLockoutCleared   AuditEvent = "auth_lockout_cleared"
	EventAllowlistBypassed    AuditEvent = "allowlist_bypassed"

	// Decision events
	EventDecisionMade AuditEvent = "decision_made"
)

// eventCategories maps each audit event to its category.
// Compliance: legal/regulatory significance, long retention required.
// Security: security monitoring, SIEM integration, alerting.
// Operations: debugging, operational visibility, can be sampled.
var eventCategories = map[AuditEvent]EventCategory{
	// Compliance events - require tamper-proof storage
	EventUserCreated:    CategoryCompliance,
	EventUserDeleted:    CategoryCompliance,
	EventConsentGranted: CategoryCompliance,
	EventConsentRevoked: CategoryCompliance,
	EventConsentDeleted: CategoryCompliance,

	// Security events - feed into SIEM and alerting
	EventAuthFailed:           CategorySecurity,
	EventSessionRevoked:       CategorySecurity,
	EventSessionsRevoked:      CategorySecurity,
	EventClientSecretRotated:  CategorySecurity,
	EventRateLimitExceeded:    CategorySecurity,
	EventAuthLockoutTriggered: CategorySecurity,
	EventAuthLockoutCleared:   CategorySecurity,
	EventAllowlistBypassed:    CategorySecurity,
	EventTenantDeactivated:    CategorySecurity,
	EventClientDeactivated:    CategorySecurity,

	// Operations events - routine activity, can be sampled
	EventSessionCreated:    CategoryOperations,
	EventTokenIssued:       CategoryOperations,
	EventTokenRefreshed:    CategoryOperations,
	EventUserInfoAccessed:  CategoryOperations,
	EventConsentChecked:    CategoryOperations,
	EventTenantCreated:     CategoryOperations,
	EventTenantReactivated: CategoryOperations,
	EventClientCreated:     CategoryOperations,
	EventClientReactivated: CategoryOperations,

	// Decision events - compliance category for regulatory requirements
	EventDecisionMade: CategoryCompliance,
}

// Category returns the EventCategory for this audit event.
// Unknown events default to CategoryOperations.
func (e AuditEvent) Category() EventCategory {
	if cat, ok := eventCategories[e]; ok {
		return cat
	}
	return CategoryOperations
}
