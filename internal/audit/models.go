package audit

import "time"

// Event is emitted from domain logic to capture key actions. Keep it
// transport-agnostic so stores and sinks can fan out.
type Event struct {
	Timestamp       time.Time
	UserID          string
	Subject         string
	Action          string
	Purpose         string
	RequestingParty string
	Decision        string
	Reason          string
}

type AuditEvent string

const (
	EventUserCreated      AuditEvent = "user_created"
	EventSessionCreated   AuditEvent = "session_created"
	EventTokenIssued      AuditEvent = "token_issued"
	EventUserInfoAccessed AuditEvent = "userinfo_accessed"
	EventAuthFailed       AuditEvent = "auth_failed"
	EventUserDeleted      AuditEvent = "user_deleted"
	EventSessionsRevoked  AuditEvent = "sessions_revoked"
)
