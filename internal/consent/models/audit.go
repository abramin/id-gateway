package models

// Audit event actions describe what operation occurred.
const (
	AuditActionConsentGranted     = "consent_granted"      // User granted consent for a purpose
	AuditActionConsentRevoked     = "consent_revoked"      // User or admin revoked consent
	AuditActionConsentDeleted     = "consent_deleted"      // Consent record permanently deleted (GDPR erasure)
	AuditActionConsentCheckPassed = "consent_check_passed" // Access granted: valid consent exists
	AuditActionConsentCheckFailed = "consent_check_failed" // Access denied: consent missing/revoked/expired
)

// Audit event decisions record the outcome of the action.
const (
	AuditDecisionGranted = "granted" // Consent was successfully granted
	AuditDecisionRevoked = "revoked" // Consent was successfully revoked
	AuditDecisionDeleted = "deleted" // Consent record was permanently erased
	AuditDecisionDenied  = "denied"  // Access denied during consent check
)

// Audit event reasons explain why the action was taken.
const (
	AuditReasonUserInitiated      = "user_initiated"       // User explicitly performed the action
	AuditReasonUserBulkRevocation = "user_bulk_revocation" // User revoked all consents at once
	AuditReasonSecurityConcern    = "security_concern"     // Admin revoked due to security incident
	AuditReasonGdprSelfService    = "gdpr_self_service"    // User requested own data deletion
	AuditReasonGdprErasureRequest = "gdpr_erasure_request" // Admin processed GDPR Art.17 erasure request
)
