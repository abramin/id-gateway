package domainerrors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

// DomainErrorsSuite tests the domain error primitives.
//
// Justification: These are core error primitives used at every trust boundary.
// Unit tests ensure invariants like "wrapped domain errors preserve original code"
// and "errors.Is matches by code" are maintained.
type DomainErrorsSuite struct {
	suite.Suite
}

func TestDomainErrorsSuite(t *testing.T) {
	suite.Run(t, new(DomainErrorsSuite))
}

func (s *DomainErrorsSuite) TestErrorInterface() {
	s.Run("returns message when present", func() {
		err := &Error{Code: CodeNotFound, Message: "user not found"}
		s.Equal("user not found", err.Error())
	})

	s.Run("returns code when message is empty", func() {
		err := &Error{Code: CodeNotFound}
		s.Equal("not_found", err.Error())
	})
}

func (s *DomainErrorsSuite) TestUnwrap() {
	s.Run("returns wrapped error", func() {
		inner := errors.New("database connection failed")
		err := &Error{Code: CodeInternal, Message: "service error", Err: inner}
		s.Equal(inner, err.Unwrap())
	})

	s.Run("returns nil when no wrapped error", func() {
		err := &Error{Code: CodeNotFound, Message: "not found"}
		s.Nil(err.Unwrap())
	})

	s.Run("works with errors.Unwrap", func() {
		inner := errors.New("root cause")
		err := &Error{Code: CodeInternal, Err: inner}
		s.Equal(inner, errors.Unwrap(err))
	})
}

func (s *DomainErrorsSuite) TestIsMatching() {
	s.Run("matches by code only", func() {
		err1 := &Error{Code: CodeNotFound, Message: "user not found"}
		err2 := &Error{Code: CodeNotFound, Message: "session not found"}
		s.True(err1.Is(err2))
	})

	s.Run("does not match different codes", func() {
		err1 := &Error{Code: CodeNotFound}
		err2 := &Error{Code: CodeInternal}
		s.False(err1.Is(err2))
	})

	s.Run("does not match non-domain errors", func() {
		err1 := &Error{Code: CodeNotFound}
		err2 := errors.New("not found")
		s.False(err1.Is(err2))
	})

	s.Run("works with errors.Is through chain", func() {
		inner := &Error{Code: CodeNotFound, Message: "original"}
		wrapped := &Error{Code: CodeInternal, Message: "wrapped", Err: inner}
		target := &Error{Code: CodeNotFound}

		// errors.Is should find the inner error through the chain
		s.True(errors.Is(wrapped, target))
	})
}

func (s *DomainErrorsSuite) TestNew() {
	s.Run("creates error with code and message", func() {
		err := New(CodeBadRequest, "invalid input")
		s.Require().NotNil(err)

		var domainErr *Error
		s.Require().True(errors.As(err, &domainErr))
		s.Equal(CodeBadRequest, domainErr.Code)
		s.Equal("invalid input", domainErr.Message)
	})
}

func (s *DomainErrorsSuite) TestWrap() {
	s.Run("preserves original domain code when wrapping domain error", func() {
		original := New(CodeNotFound, "user not found")
		wrapped := Wrap(original, CodeInternal, "service layer error")

		var domainErr *Error
		s.Require().True(errors.As(wrapped, &domainErr))
		// Should preserve CodeNotFound, not CodeInternal
		s.Equal(CodeNotFound, domainErr.Code)
		s.Equal("service layer error", domainErr.Message)
	})

	s.Run("uses provided code when wrapping non-domain error", func() {
		original := errors.New("database timeout")
		wrapped := Wrap(original, CodeInternal, "service error")

		var domainErr *Error
		s.Require().True(errors.As(wrapped, &domainErr))
		s.Equal(CodeInternal, domainErr.Code)
		s.Equal("service error", domainErr.Message)
	})

	s.Run("wrapped error is accessible via Unwrap", func() {
		original := errors.New("root cause")
		wrapped := Wrap(original, CodeInternal, "service error")

		s.True(errors.Is(wrapped, original))
	})
}

func (s *DomainErrorsSuite) TestHasCode() {
	s.Run("returns true for matching code", func() {
		err := New(CodeNotFound, "not found")
		s.True(HasCode(err, CodeNotFound))
	})

	s.Run("returns false for non-matching code", func() {
		err := New(CodeNotFound, "not found")
		s.False(HasCode(err, CodeInternal))
	})

	s.Run("returns false for non-domain error", func() {
		err := errors.New("regular error")
		s.False(HasCode(err, CodeNotFound))
	})

	s.Run("finds code through error chain", func() {
		inner := New(CodeNotFound, "original")
		wrapped := Wrap(inner, CodeInternal, "wrapped")
		// HasCode should find CodeNotFound since Wrap preserves original code
		s.True(HasCode(wrapped, CodeNotFound))
	})

	s.Run("returns false for nil error", func() {
		s.False(HasCode(nil, CodeNotFound))
	})
}
