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

type ConverterSuite struct {
	suite.Suite
}

func TestConverterSuite(t *testing.T) {
	suite.Run(t, new(ConverterSuite))
}

func (s *ConverterSuite) TestToModelConversion() {
	s.Run("converts domain credential to infrastructure model", func() {
		credID := models.NewCredentialID()
		userID := id.UserID(uuid.New())
		issuedAt := shared.MustIssuedAt(time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC))
		claims := credential.NewAgeOver18Claims(true, "national_registry")

		cred, err := credential.New(
			credID,
			models.CredentialTypeAgeOver18,
			userID,
			"credo",
			issuedAt,
			claims,
		)
		s.Require().NoError(err)

		model := credential.ToModel(cred)

		s.Equal(credID, model.ID)
		s.Equal(models.CredentialTypeAgeOver18, model.Type)
		s.Equal(userID, model.Subject)
		s.Equal("credo", model.Issuer)
		s.Equal(issuedAt.Time(), model.IssuedAt)
		s.Equal(true, model.Claims["is_over_18"])
		s.Equal("national_registry", model.Claims["verified_via"])
	})
}

func (s *ConverterSuite) TestFromModelConversion() {
	s.Run("converts infrastructure model to domain credential", func() {
		credID := models.NewCredentialID()
		userID := id.UserID(uuid.New())
		issuedAt := time.Date(2024, 7, 20, 14, 45, 0, 0, time.UTC)

		model := models.CredentialRecord{
			ID:       credID,
			Type:     models.CredentialTypeAgeOver18,
			Subject:  userID,
			Issuer:   "credo",
			IssuedAt: issuedAt,
			Claims: models.Claims{
				"is_over_18":   true,
				"verified_via": "national_registry",
			},
		}

		cred, err := credential.FromModel(model)
		s.Require().NoError(err)

		s.Equal(credID, cred.ID())
		s.Equal(models.CredentialTypeAgeOver18, cred.Type())
		s.Equal(userID, cred.Subject())
		s.Equal("credo", cred.Issuer())
		s.Equal(issuedAt, cred.IssuedAt().Time())

		// Verify claims were reconstructed as typed AgeOver18Claims
		claimsMap := cred.Claims().ToMap()
		s.Equal(true, claimsMap["is_over_18"])
		s.Equal("national_registry", claimsMap["verified_via"])
	})

	s.Run("rejects model with zero issued_at", func() {
		model := models.CredentialRecord{
			ID:       models.NewCredentialID(),
			Type:     models.CredentialTypeAgeOver18,
			Subject:  id.UserID(uuid.New()),
			Issuer:   "credo",
			IssuedAt: time.Time{}, // zero value
			Claims:   models.Claims{"is_over_18": true},
		}

		_, err := credential.FromModel(model)
		s.Require().Error(err)
	})

	s.Run("rejects unknown credential type", func() {
		model := models.CredentialRecord{
			ID:       models.NewCredentialID(),
			Type:     models.CredentialType("UnknownType"),
			Subject:  id.UserID(uuid.New()),
			Issuer:   "credo",
			IssuedAt: time.Now(),
			Claims:   models.Claims{"some_claim": true},
		}

		_, err := credential.FromModel(model)
		s.Require().Error(err)
		s.Contains(err.Error(), "unknown credential type")
	})
}

func (s *ConverterSuite) TestRoundtrip() {
	s.Run("AgeOver18 credential survives roundtrip", func() {
		// Create original domain credential
		credID := models.NewCredentialID()
		userID := id.UserID(uuid.New())
		issuedAt := shared.MustIssuedAt(time.Date(2024, 8, 1, 9, 0, 0, 0, time.UTC))
		claims := credential.NewAgeOver18Claims(true, "national_registry")

		original, err := credential.New(
			credID,
			models.CredentialTypeAgeOver18,
			userID,
			"credo",
			issuedAt,
			claims,
		)
		s.Require().NoError(err)

		// Convert to model
		model := credential.ToModel(original)

		// Convert back to domain
		restored, err := credential.FromModel(model)
		s.Require().NoError(err)

		// Verify all fields match
		s.Equal(original.ID(), restored.ID())
		s.Equal(original.Type(), restored.Type())
		s.Equal(original.Subject(), restored.Subject())
		s.Equal(original.Issuer(), restored.Issuer())
		s.Equal(original.IssuedAt().Time(), restored.IssuedAt().Time())

		// Verify claims match
		originalMap := original.Claims().ToMap()
		restoredMap := restored.Claims().ToMap()
		s.Equal(originalMap["is_over_18"], restoredMap["is_over_18"])
		s.Equal(originalMap["verified_via"], restoredMap["verified_via"])
	})

	s.Run("minimized credential survives roundtrip", func() {
		credID := models.NewCredentialID()
		userID := id.UserID(uuid.New())
		issuedAt := shared.MustIssuedAt(time.Now())
		claims := credential.NewAgeOver18Claims(true, "national_registry")

		original, err := credential.New(
			credID,
			models.CredentialTypeAgeOver18,
			userID,
			"credo",
			issuedAt,
			claims,
		)
		s.Require().NoError(err)

		// Minimize before roundtrip
		minimized := original.Minimized()

		// Convert to model
		model := credential.ToModel(minimized)

		// Verify verified_via is NOT in the model claims
		_, hasVerifiedVia := model.Claims["verified_via"]
		s.False(hasVerifiedVia)

		// Convert back to domain
		restored, err := credential.FromModel(model)
		s.Require().NoError(err)

		// Verify claims are still minimized
		restoredMap := restored.Claims().ToMap()
		s.Equal(true, restoredMap["is_over_18"])
		_, hasVerifiedViaRestored := restoredMap["verified_via"]
		s.False(hasVerifiedViaRestored)
	})
}
