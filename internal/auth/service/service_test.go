package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func (s *ServiceSuite) TestNewService_RequiresDepsAndConfig() {
	s.T().Run("missing stores fails", func(t *testing.T) {
		_, err := New(nil, nil, nil, nil, &Config{})
		require.Error(t, err)
	})

	s.T().Run("sets defaults and applies jwt", func(t *testing.T) {
		svc, err := New(
			s.mockUserStore,
			s.mockSessionStore,
			s.mockCodeStore,
			s.mockRefreshStore,
			&Config{}, // empty config
			WithJWTService(s.mockJWT),
		)
		require.NoError(t, err)
		s.Equal(defaultSessionTTL, svc.SessionTTL)
		s.Equal(defaultTokenTTL, svc.TokenTTL)
		s.Equal([]string{"https"}, svc.AllowedRedirectSchemes)
		s.Equal(s.mockJWT, svc.jwt)
	})
}
