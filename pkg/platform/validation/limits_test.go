package validation

import (
	"strings"
	"testing"

	dErrors "credo/pkg/domain-errors"

	"github.com/stretchr/testify/suite"
)

// LimitsSuite tests the validation helper functions.
//
// Justification: These are trust-boundary validators. The invariants
// "max+1 must fail" and "max must pass" are security-critical.
type LimitsSuite struct {
	suite.Suite
}

func TestLimitsSuite(t *testing.T) {
	suite.Run(t, new(LimitsSuite))
}

func (s *LimitsSuite) TestCheckSliceCount() {
	s.Run("passes when count equals max", func() {
		err := CheckSliceCount("scopes", 20, 20)
		s.NoError(err)
	})

	s.Run("passes when count is below max", func() {
		err := CheckSliceCount("scopes", 5, 20)
		s.NoError(err)
	})

	s.Run("passes when count is zero", func() {
		err := CheckSliceCount("scopes", 0, 20)
		s.NoError(err)
	})

	s.Run("fails when count exceeds max", func() {
		err := CheckSliceCount("scopes", 21, 20)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation))
		s.Contains(err.Error(), "too many scopes")
		s.Contains(err.Error(), "max 20 allowed")
	})
}

func (s *LimitsSuite) TestCheckStringLength() {
	s.Run("passes when length equals max", func() {
		str := strings.Repeat("a", 100)
		err := CheckStringLength("scope", str, 100)
		s.NoError(err)
	})

	s.Run("passes when length is below max", func() {
		err := CheckStringLength("scope", "short", 100)
		s.NoError(err)
	})

	s.Run("passes for empty string", func() {
		err := CheckStringLength("scope", "", 100)
		s.NoError(err)
	})

	s.Run("fails when length exceeds max", func() {
		str := strings.Repeat("a", 101)
		err := CheckStringLength("scope", str, 100)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation))
		s.Contains(err.Error(), "scope exceeds max length of 100")
	})
}

func (s *LimitsSuite) TestCheckEachStringLength() {
	s.Run("passes when all elements are within limit", func() {
		values := []string{"short", "also short", strings.Repeat("a", 100)}
		err := CheckEachStringLength("scope", values, 100)
		s.NoError(err)
	})

	s.Run("passes for empty slice", func() {
		err := CheckEachStringLength("scope", []string{}, 100)
		s.NoError(err)
	})

	s.Run("passes for nil slice", func() {
		err := CheckEachStringLength("scope", nil, 100)
		s.NoError(err)
	})

	s.Run("fails when any element exceeds max", func() {
		values := []string{"short", strings.Repeat("a", 101), "also short"}
		err := CheckEachStringLength("scope", values, 100)
		s.Require().Error(err)
		s.True(dErrors.HasCode(err, dErrors.CodeValidation))
		s.Contains(err.Error(), "scope exceeds max length of 100")
	})

	s.Run("fails on first exceeding element", func() {
		values := []string{strings.Repeat("a", 101), strings.Repeat("b", 102)}
		err := CheckEachStringLength("scope", values, 100)
		s.Require().Error(err)
		// Only one error, not multiple
		s.Contains(err.Error(), "scope exceeds max length of 100")
	})
}
