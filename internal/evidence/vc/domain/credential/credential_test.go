package credential_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/vc/domain/credential"
	"credo/internal/evidence/vc/domain/shared"
	"credo/internal/evidence/vc/models"
	id "credo/pkg/domain"
)

type CredentialSuite struct {
	suite.Suite
	validID       models.CredentialID
	validType     models.CredentialType
	validSubject  id.UserID
	validIssuer   string
	validIssuedAt shared.IssuedAt
	validClaims   credential.ClaimSet
}

func TestCredentialSuite(t *testing.T) {
	suite.Run(t, new(CredentialSuite))
}

func (s *CredentialSuite) SetupTest() {
	s.validID = models.NewCredentialID()
	s.validType = models.CredentialTypeAgeOver18
	s.validSubject = id.UserID(uuid.New())
	s.validIssuer = "credo"
	s.validIssuedAt = mustIssuedAt(time.Now())
	s.validClaims = credential.NewAgeOver18Claims(true, "national_registry")
}

func (s *CredentialSuite) TestConstructionInvariants() {
	cases := []struct {
		name     string
		id       models.CredentialID
		credType models.CredentialType
		subject  id.UserID
		issuer   string
		issuedAt shared.IssuedAt
		claims   credential.ClaimSet
		wantErr  bool
		errField string
	}{
		{
			name: "rejects empty credential ID", id: "", credType: s.validType,
			subject: s.validSubject, issuer: s.validIssuer, issuedAt: s.validIssuedAt, claims: s.validClaims,
			wantErr: true, errField: "credential_id",
		},
		{
			name: "rejects nil subject", id: s.validID, credType: s.validType,
			subject: id.UserID{}, issuer: s.validIssuer, issuedAt: s.validIssuedAt, claims: s.validClaims,
			wantErr: true, errField: "subject",
		},
		{
			name: "rejects empty issuer", id: s.validID, credType: s.validType,
			subject: s.validSubject, issuer: "", issuedAt: s.validIssuedAt, claims: s.validClaims,
			wantErr: true, errField: "issuer",
		},
		{
			name: "rejects zero issued_at", id: s.validID, credType: s.validType,
			subject: s.validSubject, issuer: s.validIssuer, issuedAt: shared.IssuedAt{}, claims: s.validClaims,
			wantErr: true, errField: "issued_at",
		},
		{
			name: "rejects nil claims", id: s.validID, credType: s.validType,
			subject: s.validSubject, issuer: s.validIssuer, issuedAt: s.validIssuedAt, claims: nil,
			wantErr: true, errField: "claims",
		},
		{
			name: "accepts valid inputs", id: s.validID, credType: s.validType,
			subject: s.validSubject, issuer: s.validIssuer, issuedAt: s.validIssuedAt, claims: s.validClaims,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			cred, err := credential.New(tc.id, tc.credType, tc.subject, tc.issuer, tc.issuedAt, tc.claims)
			if tc.wantErr {
				s.Require().Error(err)
				s.Contains(err.Error(), tc.errField)
			} else {
				s.Require().NoError(err)
				s.NotNil(cred)
				s.Equal(tc.id, cred.ID())
				s.Equal(tc.credType, cred.Type())
				s.Equal(tc.subject, cred.Subject())
				s.Equal(tc.issuer, cred.Issuer())
				s.False(cred.IsMinimized())
			}
		})
	}
}

func (s *CredentialSuite) TestMinimization() {
	s.Run("returns new credential without mutating original", func() {
		original, err := credential.New(
			s.validID,
			s.validType,
			s.validSubject,
			s.validIssuer,
			s.validIssuedAt,
			s.validClaims,
		)
		s.Require().NoError(err)

		minimized := original.Minimized()

		// Original should be unchanged
		s.False(original.IsMinimized())

		// Minimized should be marked as such
		s.True(minimized.IsMinimized())

		// Both should have same ID and metadata
		s.Equal(original.ID(), minimized.ID())
		s.Equal(original.Type(), minimized.Type())
		s.Equal(original.Subject(), minimized.Subject())
		s.Equal(original.Issuer(), minimized.Issuer())
	})

	s.Run("strips verified_via from AgeOver18 claims", func() {
		claims := credential.NewAgeOver18Claims(true, "national_registry")
		original, err := credential.New(
			s.validID,
			s.validType,
			s.validSubject,
			s.validIssuer,
			s.validIssuedAt,
			claims,
		)
		s.Require().NoError(err)

		minimized := original.Minimized()

		// Original claims should have verified_via
		originalMap := original.Claims().ToMap()
		s.Contains(originalMap, "verified_via")

		// Minimized claims should NOT have verified_via
		minimizedMap := minimized.Claims().ToMap()
		s.NotContains(minimizedMap, "verified_via")

		// But should still have is_over_18
		s.Contains(minimizedMap, "is_over_18")
		s.Equal(true, minimizedMap["is_over_18"])
	})
}

func mustIssuedAt(t time.Time) shared.IssuedAt {
	issuedAt, err := shared.NewIssuedAt(t)
	if err != nil {
		panic(err)
	}
	return issuedAt
}
