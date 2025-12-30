package shared_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/vc/domain/shared"
)

type ValueObjectsSuite struct {
	suite.Suite
}

func TestValueObjectsSuite(t *testing.T) {
	suite.Run(t, new(ValueObjectsSuite))
}

func (s *ValueObjectsSuite) TestIssuedAtConstruction() {
	now := time.Now()
	cases := []struct {
		name    string
		t       time.Time
		wantErr bool
	}{
		{"rejects zero time", time.Time{}, true},
		{"accepts valid time", now, false},
		{"accepts past time", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"accepts future time", now.Add(24 * time.Hour), false},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			issuedAt, err := shared.NewIssuedAt(tc.t)
			if tc.wantErr {
				s.Require().Error(err)
				s.ErrorIs(err, shared.ErrInvalidIssuedAt)
			} else {
				s.Require().NoError(err)
				s.Equal(tc.t, issuedAt.Time())
			}
		})
	}
}

func (s *ValueObjectsSuite) TestIssuedAtMust() {
	s.Run("panics on zero time", func() {
		s.Panics(func() {
			shared.MustIssuedAt(time.Time{})
		})
	})

	s.Run("returns value on valid time", func() {
		now := time.Now()
		s.NotPanics(func() {
			issuedAt := shared.MustIssuedAt(now)
			s.Equal(now, issuedAt.Time())
		})
	})
}

func (s *ValueObjectsSuite) TestIssuedAtIsZero() {
	s.Run("zero value IssuedAt is zero", func() {
		var issuedAt shared.IssuedAt
		s.True(issuedAt.IsZero())
	})

	s.Run("valid IssuedAt is not zero", func() {
		issuedAt := shared.MustIssuedAt(time.Now())
		s.False(issuedAt.IsZero())
	})
}

func (s *ValueObjectsSuite) TestExpiresAtConstruction() {
	s.Run("rejects zero time", func() {
		_, err := shared.NewExpiresAt(time.Time{})
		s.Require().Error(err)
		s.ErrorIs(err, shared.ErrInvalidExpiresAt)
	})

	s.Run("accepts valid time", func() {
		future := time.Now().Add(24 * time.Hour)
		expiresAt, err := shared.NewExpiresAt(future)
		s.Require().NoError(err)
		s.Equal(future, expiresAt.Time())
	})
}

func (s *ValueObjectsSuite) TestExpiresAtAfterConstruction() {
	now := time.Now()
	issuedAt := shared.MustIssuedAt(now)

	cases := []struct {
		name         string
		expiresAt    time.Time
		wantErr      bool
		wantSentinel error
	}{
		{"rejects zero time", time.Time{}, true, shared.ErrInvalidExpiresAt},
		{"rejects expiration before issuance", now.Add(-1 * time.Hour), true, shared.ErrExpiresBeforeIssued},
		{"rejects expiration equal to issuance", now, true, shared.ErrExpiresBeforeIssued},
		{"accepts expiration after issuance", now.Add(24 * time.Hour), false, nil},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			expiresAt, err := shared.NewExpiresAtAfter(tc.expiresAt, issuedAt)
			if tc.wantErr {
				s.Require().Error(err)
				s.ErrorIs(err, tc.wantSentinel)
			} else {
				s.Require().NoError(err)
				s.Equal(tc.expiresAt, expiresAt.Time())
			}
		})
	}
}

func (s *ValueObjectsSuite) TestNoExpiration() {
	s.Run("returns zero ExpiresAt for permanent credentials", func() {
		exp := shared.NoExpiration()
		s.True(exp.IsZero())
	})
}

func (s *ValueObjectsSuite) TestExpiresAtIsZero() {
	s.Run("zero value ExpiresAt is zero", func() {
		var expiresAt shared.ExpiresAt
		s.True(expiresAt.IsZero())
	})

	s.Run("NoExpiration is zero", func() {
		expiresAt := shared.NoExpiration()
		s.True(expiresAt.IsZero())
	})

	s.Run("valid ExpiresAt is not zero", func() {
		expiresAt, _ := shared.NewExpiresAt(time.Now().Add(time.Hour))
		s.False(expiresAt.IsZero())
	})
}

func (s *ValueObjectsSuite) TestExpiresAtIsExpiredAt() {
	now := time.Now()
	expirationTime := now.Add(time.Hour)

	cases := []struct {
		name      string
		expiresAt shared.ExpiresAt
		checkAt   time.Time
		expired   bool
	}{
		{"permanent credential never expires (now)", shared.NoExpiration(), now, false},
		{"permanent credential never expires (far future)", shared.NoExpiration(), now.Add(100 * 365 * 24 * time.Hour), false},
		{"not expired before expiration time", mustExpiresAt(expirationTime), now, false},
		{"expired after expiration time", mustExpiresAt(now.Add(-1 * time.Hour)), now, true},
		{"not expired at exact expiration time", mustExpiresAt(expirationTime), expirationTime, false},
		{"expired one nanosecond after expiration time", mustExpiresAt(expirationTime), expirationTime.Add(time.Nanosecond), true},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.Equal(tc.expired, tc.expiresAt.IsExpiredAt(tc.checkAt))
		})
	}
}

func mustExpiresAt(t time.Time) shared.ExpiresAt {
	exp, _ := shared.NewExpiresAt(t)
	return exp
}
