package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		assert.Equal(t, defaultSessionTTL, svc.SessionTTL)
		assert.Equal(t, defaultTokenTTL, svc.TokenTTL)
		assert.Equal(t, []string{"https"}, svc.AllowedRedirectSchemes)
		assert.Equal(t, s.mockJWT, svc.jwt)
	})
}
