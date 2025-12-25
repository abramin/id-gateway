package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func (s *ServiceSuite) TestNewService_RequiresDepsAndConfig() {
	s.T().Run("missing stores fails", func(t *testing.T) {
		_, err := New(nil, nil, nil, nil, s.mockJWT, s.mockClientResolver, &Config{})
		require.Error(t, err)
	})

	s.T().Run("missing jwt fails", func(t *testing.T) {
		_, err := New(s.mockUserStore, s.mockSessionStore, s.mockCodeStore, s.mockRefreshStore, nil, s.mockClientResolver, &Config{})
		require.Error(t, err)
	})

	s.T().Run("missing client resolver fails", func(t *testing.T) {
		_, err := New(s.mockUserStore, s.mockSessionStore, s.mockCodeStore, s.mockRefreshStore, s.mockJWT, nil, &Config{})
		require.Error(t, err)
	})

	s.T().Run("sets defaults with required deps", func(t *testing.T) {
		svc, err := New(
			s.mockUserStore,
			s.mockSessionStore,
			s.mockCodeStore,
			s.mockRefreshStore,
			s.mockJWT,
			s.mockClientResolver,
			&Config{}, // empty config
		)
		require.NoError(t, err)
		s.Equal(defaultSessionTTL, svc.SessionTTL)
		s.Equal(defaultTokenTTL, svc.TokenTTL)
		s.Equal([]string{"https"}, svc.AllowedRedirectSchemes)
		s.Equal(s.mockJWT, svc.jwt)
		s.Equal(s.mockClientResolver, svc.clientResolver)
	})
}
