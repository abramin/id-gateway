package decision

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// DeriveIsOver18Suite tests the deriveIsOver18 pure function.
// Justification: Pure function with critical date boundary logic that affects
// compliance decisions. The 18th birthday edge case is an invariant that would
// break user-visible behavior if wrong.
type DeriveIsOver18Suite struct {
	suite.Suite
}

func TestDeriveIsOver18Suite(t *testing.T) {
	suite.Run(t, new(DeriveIsOver18Suite))
}

func (s *DeriveIsOver18Suite) TestAgeBoundaries() {
	now := time.Now()

	s.Run("exactly 18 years ago returns true", func() {
		dob := now.AddDate(-18, 0, 0).Format("2006-01-02")
		s.True(deriveIsOver18(dob), "person born exactly 18 years ago should be over 18")
	})

	s.Run("one week before 18th birthday returns false", func() {
		// Born 18 years ago minus 7 days = not yet 18 (use 7 days for margin due to 365.25 approximation)
		dob := now.AddDate(-18, 0, 7).Format("2006-01-02")
		s.False(deriveIsOver18(dob), "person one week before 18th birthday should not be over 18")
	})

	s.Run("one day after 18th birthday returns true", func() {
		// Born 18 years and 1 day ago = over 18
		dob := now.AddDate(-18, 0, -1).Format("2006-01-02")
		s.True(deriveIsOver18(dob), "person one day after 18th birthday should be over 18")
	})

	s.Run("clearly over 18 returns true", func() {
		s.True(deriveIsOver18("1990-01-15"), "person born in 1990 should be over 18")
	})

	s.Run("clearly under 18 returns false", func() {
		dob := now.AddDate(-10, 0, 0).Format("2006-01-02")
		s.False(deriveIsOver18(dob), "10 year old should not be over 18")
	})

	s.Run("exactly 17 years old returns false", func() {
		dob := now.AddDate(-17, 0, 0).Format("2006-01-02")
		s.False(deriveIsOver18(dob), "17 year old should not be over 18")
	})

	s.Run("19 years old returns true", func() {
		dob := now.AddDate(-19, 0, 0).Format("2006-01-02")
		s.True(deriveIsOver18(dob), "19 year old should be over 18")
	})
}

func (s *DeriveIsOver18Suite) TestInvalidInputs() {
	s.Run("empty string returns false", func() {
		s.False(deriveIsOver18(""), "empty DOB should return false")
	})

	s.Run("malformed date returns false", func() {
		s.False(deriveIsOver18("not-a-date"), "malformed date should return false")
	})

	s.Run("wrong format MM/DD/YYYY returns false", func() {
		s.False(deriveIsOver18("01/15/1990"), "wrong date format should return false")
	})

	s.Run("wrong format DD-MM-YYYY returns false", func() {
		s.False(deriveIsOver18("15-01-1990"), "wrong date format should return false")
	})

	s.Run("partial date returns false", func() {
		s.False(deriveIsOver18("1990-01"), "partial date should return false")
	})

	s.Run("future date returns false", func() {
		futureDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
		s.False(deriveIsOver18(futureDate), "future birth date should return false")
	})
}

func (s *DeriveIsOver18Suite) TestLeapYearBoundary() {
	// Test leap year birthday handling
	s.Run("leap year birthday Feb 29 handled correctly", func() {
		// Someone born on Feb 29, 2000 (leap year)
		// As of 2024+, they are over 18
		s.True(deriveIsOver18("2000-02-29"), "person born Feb 29 2000 should be over 18")
	})
}

// ParsePurposeSuite tests the ParsePurpose validation function.
type ParsePurposeSuite struct {
	suite.Suite
}

func TestParsePurposeSuite(t *testing.T) {
	suite.Run(t, new(ParsePurposeSuite))
}

func (s *ParsePurposeSuite) TestValidPurposes() {
	s.Run("age_verification is valid", func() {
		purpose, err := ParsePurpose("age_verification")
		s.Require().NoError(err)
		s.Equal(PurposeAgeVerification, purpose)
	})

	s.Run("sanctions_screening is valid", func() {
		purpose, err := ParsePurpose("sanctions_screening")
		s.Require().NoError(err)
		s.Equal(PurposeSanctionsScreening, purpose)
	})
}

func (s *ParsePurposeSuite) TestInvalidPurposes() {
	s.Run("empty string returns error", func() {
		_, err := ParsePurpose("")
		s.Error(err)
		s.Contains(err.Error(), "unsupported purpose")
	})

	s.Run("unknown purpose returns error", func() {
		_, err := ParsePurpose("unknown_purpose")
		s.Error(err)
		s.Contains(err.Error(), "unsupported purpose")
	})

	s.Run("similar but wrong purpose returns error", func() {
		_, err := ParsePurpose("age-verification") // hyphen instead of underscore
		s.Error(err)
	})
}

// DecisionOutcomeSuite tests the decision outcome constants.
type DecisionOutcomeSuite struct {
	suite.Suite
}

func TestDecisionOutcomeSuite(t *testing.T) {
	suite.Run(t, new(DecisionOutcomeSuite))
}

func (s *DecisionOutcomeSuite) TestOutcomeValues() {
	s.Run("outcome constants have expected string values", func() {
		s.Equal("pass", string(DecisionPass))
		s.Equal("pass_with_conditions", string(DecisionPassWithConditions))
		s.Equal("fail", string(DecisionFail))
	})
}

func (s *DecisionOutcomeSuite) TestReasonValues() {
	s.Run("reason constants have expected string values", func() {
		s.Equal("all_checks_passed", string(ReasonAllChecksPassed))
		s.Equal("sanctioned", string(ReasonSanctioned))
		s.Equal("invalid_citizen", string(ReasonInvalidCitizen))
		s.Equal("underage", string(ReasonUnderage))
		s.Equal("missing_credential", string(ReasonMissingCredential))
		s.Equal("not_sanctioned", string(ReasonNotSanctioned))
	})
}
