package audit

import (
	"time"

	id "credo/pkg/domain"
)

// Event is emitted from domain logic to capture key actions. Keep it
// transport-agnostic so stores and sinks can fan out.
type Event struct {
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
}

type AuditEvent string

const (
	EventUserCreated      AuditEvent = "user_created"
	EventSessionCreated   AuditEvent = "session_created"
	EventSessionRevoked   AuditEvent = "session_revoked"
	EventTokenIssued      AuditEvent = "token_issued"
	EventTokenRefreshed   AuditEvent = "token_refreshed"
	EventUserInfoAccessed AuditEvent = "userinfo_accessed"
	EventAuthFailed       AuditEvent = "auth_failed"
	EventUserDeleted      AuditEvent = "user_deleted"
	EventSessionsRevoked  AuditEvent = "sessions_revoked"
	EventTenantCreated    AuditEvent = "tenant_created"
	EventClientCreated    AuditEvent = "client_created"
	EventSecretRotated    AuditEvent = "secret_rotated"
)
