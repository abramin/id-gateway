package service

// AGENTS.MD JUSTIFICATION: Constructor validation/defaulting prevents misconfiguration
// and is not covered by feature tests.
func (s *ServiceSuite) TestServiceConstruction_RequiresDependencies() {
	s.Run("missing stores fails", func() {
		_, err := New(nil, nil, nil, nil, s.mockJWT, s.mockClientResolver, &Config{})
		s.Require().Error(err)
	})

	s.Run("missing jwt fails", func() {
		_, err := New(s.mockUserStore, s.mockSessionStore, s.mockCodeStore, s.mockRefreshStore, nil, s.mockClientResolver, &Config{})
		s.Require().Error(err)
	})

	s.Run("missing client resolver fails", func() {
		_, err := New(s.mockUserStore, s.mockSessionStore, s.mockCodeStore, s.mockRefreshStore, s.mockJWT, nil, &Config{})
		s.Require().Error(err)
	})

	s.Run("sets defaults with required deps", func() {
		svc, err := New(
			s.mockUserStore,
			s.mockSessionStore,
			s.mockCodeStore,
			s.mockRefreshStore,
			s.mockJWT,
			s.mockClientResolver,
			&Config{}, // empty config
		)
		s.Require().NoError(err)
		s.Equal(defaultSessionTTL, svc.SessionTTL)
		s.Equal(defaultTokenTTL, svc.TokenTTL)
		s.Equal([]string{"https"}, svc.AllowedRedirectSchemes)
		s.Equal(s.mockJWT, svc.jwt)
		s.Equal(s.mockClientResolver, svc.clientResolver)
	})
}
