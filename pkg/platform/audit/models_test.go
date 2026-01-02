package audit

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

// AuditEventSuite tests the AuditEvent type and category mapping.
//
// Justification: The Category() method has a fallback to CategoryOperations
// for unknown events. This is a security/compliance invariant that ensures
// miscategorization cannot cause compliance events to be lost.
type AuditEventSuite struct {
	suite.Suite
}

func TestAuditEventSuite(t *testing.T) {
	suite.Run(t, new(AuditEventSuite))
}

func (s *AuditEventSuite) TestCategory_ComplianceEvents() {
	complianceEvents := []AuditEvent{
		EventUserCreated,
		EventUserDeleted,
		EventConsentGranted,
		EventConsentRevoked,
		EventConsentDeleted,
		EventDecisionMade,
	}

	for _, event := range complianceEvents {
		s.Run(string(event), func() {
			s.Equal(CategoryCompliance, event.Category())
		})
	}
}

func (s *AuditEventSuite) TestCategory_SecurityEvents() {
	securityEvents := []AuditEvent{
		EventAuthFailed,
		EventSessionRevoked,
		EventSessionsRevoked,
		EventClientSecretRotated,
		EventRateLimitExceeded,
		EventAuthLockoutTriggered,
		EventAuthLockoutCleared,
		EventAllowlistBypassed,
		EventTenantDeactivated,
		EventClientDeactivated,
	}

	for _, event := range securityEvents {
		s.Run(string(event), func() {
			s.Equal(CategorySecurity, event.Category())
		})
	}
}

func (s *AuditEventSuite) TestCategory_OperationsEvents() {
	operationsEvents := []AuditEvent{
		EventSessionCreated,
		EventTokenIssued,
		EventTokenRefreshed,
		EventUserInfoAccessed,
		EventConsentChecked,
		EventTenantCreated,
		EventTenantReactivated,
		EventClientCreated,
		EventClientReactivated,
	}

	for _, event := range operationsEvents {
		s.Run(string(event), func() {
			s.Equal(CategoryOperations, event.Category())
		})
	}
}

func (s *AuditEventSuite) TestCategory_UnknownEventDefaultsToOperations() {
	// Unknown events should default to CategoryOperations
	// This is a safety fallback - unknown events are treated as low-priority
	// rather than being miscategorized as compliance/security
	unknownEvent := AuditEvent("unknown_event_type")
	s.Equal(CategoryOperations, unknownEvent.Category())
}

func (s *AuditEventSuite) TestCategory_EmptyEventDefaultsToOperations() {
	emptyEvent := AuditEvent("")
	s.Equal(CategoryOperations, emptyEvent.Category())
}
