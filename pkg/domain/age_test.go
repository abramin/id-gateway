package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// AgeSuite tests age calculation functions.
//
// Justification: Pure function with date arithmetic edge cases.
// The invariant "exactly 18th birthday is over 18" must be preserved.
type AgeSuite struct {
	suite.Suite
}

func TestAgeSuite(t *testing.T) {
	suite.Run(t, new(AgeSuite))
}

func (s *AgeSuite) TestIsOver18_BirthdayBoundaries() {
	s.Run("exactly 18th birthday returns true", func() {
		birthDate := time.Date(2000, 1, 15, 0, 0, 0, 0, time.UTC)
		now := time.Date(2018, 1, 15, 0, 0, 0, 0, time.UTC)
		s.True(IsOver18(birthDate, now))
	})

	s.Run("day before 18th birthday returns false", func() {
		birthDate := time.Date(2000, 1, 15, 0, 0, 0, 0, time.UTC)
		now := time.Date(2018, 1, 14, 23, 59, 59, 0, time.UTC)
		s.False(IsOver18(birthDate, now))
	})

	s.Run("day after 18th birthday returns true", func() {
		birthDate := time.Date(2000, 1, 15, 0, 0, 0, 0, time.UTC)
		now := time.Date(2018, 1, 16, 0, 0, 0, 0, time.UTC)
		s.True(IsOver18(birthDate, now))
	})
}

func (s *AgeSuite) TestIsOver18_LeapYearEdgeCases() {
	s.Run("Feb 29 birthday on non-leap year 18th birthday (Mar 1)", func() {
		// Born on Feb 29, 2000 (leap year)
		// 18th birthday in 2018 (not a leap year) - Feb 29 doesn't exist
		// AddDate(18, 0, 0) should give Mar 1, 2018
		birthDate := time.Date(2000, 2, 29, 0, 0, 0, 0, time.UTC)
		mar1_2018 := time.Date(2018, 3, 1, 0, 0, 0, 0, time.UTC)
		s.True(IsOver18(birthDate, mar1_2018))
	})

	s.Run("Feb 29 birthday on leap year 18th birthday", func() {
		// Born on Feb 29, 2004 (leap year)
		// 18th birthday in 2022 (not a leap year)
		birthDate := time.Date(2004, 2, 29, 0, 0, 0, 0, time.UTC)
		mar1_2022 := time.Date(2022, 3, 1, 0, 0, 0, 0, time.UTC)
		s.True(IsOver18(birthDate, mar1_2022))
	})

	s.Run("Feb 28 on non-leap year for Feb 29 birthday is not yet 18", func() {
		birthDate := time.Date(2000, 2, 29, 0, 0, 0, 0, time.UTC)
		feb28_2018 := time.Date(2018, 2, 28, 0, 0, 0, 0, time.UTC)
		s.False(IsOver18(birthDate, feb28_2018))
	})
}

func (s *AgeSuite) TestIsOver18_TimezoneHandling() {
	s.Run("different timezones are normalized to UTC", func() {
		// Both dates are converted to UTC internally
		pst := time.FixedZone("PST", -8*60*60)
		birthDate := time.Date(2000, 1, 15, 0, 0, 0, 0, pst)
		now := time.Date(2018, 1, 15, 8, 0, 0, 0, time.UTC) // Same instant as midnight PST

		s.True(IsOver18(birthDate, now))
	})
}

func (s *AgeSuite) TestIsOver18_EdgeAges() {
	s.Run("17 years old returns false", func() {
		birthDate := time.Date(2000, 6, 15, 0, 0, 0, 0, time.UTC)
		now := time.Date(2017, 6, 15, 0, 0, 0, 0, time.UTC)
		s.False(IsOver18(birthDate, now))
	})

	s.Run("19 years old returns true", func() {
		birthDate := time.Date(2000, 6, 15, 0, 0, 0, 0, time.UTC)
		now := time.Date(2019, 6, 15, 0, 0, 0, 0, time.UTC)
		s.True(IsOver18(birthDate, now))
	})

	s.Run("much older returns true", func() {
		birthDate := time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC)
		now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		s.True(IsOver18(birthDate, now))
	})
}
