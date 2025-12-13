package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MockJWTValidator is a testify mock for JWTValidator
type MockJWTValidator struct {
	mock.Mock
}

func (m *MockJWTValidator) ValidateToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	if claims := args.Get(0); claims != nil {
		return claims.(*JWTClaims), args.Error(1)
	}
	return nil, args.Error(1)
}

type MockTokenRevocationChecker struct {
	mock.Mock
}

func (m *MockTokenRevocationChecker) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)
	return args.Bool(0), args.Error(1)
}

// mockHandler is a test handler that captures if it was called and the context
type mockHandler struct {
	called  bool
	context context.Context
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.called = true
	m.context = r.Context()
	w.WriteHeader(http.StatusOK)
}

func (m *mockHandler) reset() {
	m.called = false
	m.context = nil
}

// AuthMiddlewareTestSuite is the test suite for auth middleware
type AuthMiddlewareTestSuite struct {
	suite.Suite
	validator   *MockJWTValidator
	revoker     *MockTokenRevocationChecker
	logger      *slog.Logger
	nextHandler *mockHandler
	middleware  func(http.Handler) http.Handler
}

func (s *AuthMiddlewareTestSuite) SetupTest() {
	s.validator = new(MockJWTValidator)
	s.revoker = new(MockTokenRevocationChecker)
	s.logger = slog.Default()
	s.nextHandler = &mockHandler{}
	s.middleware = RequireAuth(s.validator, nil, s.logger) // nil for revocation checker in tests
}

func (s *AuthMiddlewareTestSuite) TearDownTest() {
	s.validator.AssertExpectations(s.T())
	s.revoker.AssertExpectations(s.T())
}

func (s *AuthMiddlewareTestSuite) makeRequest(authHeader string) *httptest.ResponseRecorder {
	handler := s.middleware(s.nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func (s *AuthMiddlewareTestSuite) TestValidToken() {
	expectedClaims := &JWTClaims{
		UserID:    "user-123",
		SessionID: "session-456",
		ClientID:  "client-789",
	}
	s.validator.On("ValidateToken", "valid-token").Return(expectedClaims, nil)

	w := s.makeRequest("Bearer valid-token")

	require.True(s.T(), s.nextHandler.called, "next handler should be called")
	assert.Equal(s.T(), http.StatusOK, w.Code)

	// Verify context values were set correctly
	assert.Equal(s.T(), "user-123", GetUserID(s.nextHandler.context))
	assert.Equal(s.T(), "session-456", GetSessionID(s.nextHandler.context))
	assert.Equal(s.T(), "client-789", GetClientID(s.nextHandler.context))
}

func (s *AuthMiddlewareTestSuite) TestRevokedToken() {
	expectedClaims := &JWTClaims{
		UserID:    "user-123",
		SessionID: "session-456",
		ClientID:  "client-789",
		JTI:       "jti-123",
	}
	s.validator.On("ValidateToken", "valid-token").Return(expectedClaims, nil)
	s.revoker.On("IsTokenRevoked", mock.Anything, "jti-123").Return(true, nil)

	handler := RequireAuth(s.validator, s.revoker, s.logger)(s.nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called")
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
	assert.JSONEq(s.T(),
		`{"error":"unauthorized","error_description":"Token has been revoked"}`,
		w.Body.String(),
	)
}

func (s *AuthMiddlewareTestSuite) TestInvalidToken() {
	s.validator.On("ValidateToken", "invalid-token").Return(nil, errors.New("token expired"))

	w := s.makeRequest("Bearer invalid-token")

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called")
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
	assert.Equal(s.T(), "application/json", w.Header().Get("Content-Type"))
	assert.JSONEq(s.T(),
		`{"error":"unauthorized","error_description":"Invalid or expired token"}`,
		w.Body.String(),
	)
}

func (s *AuthMiddlewareTestSuite) TestMissingAuthorizationHeader() {
	w := s.makeRequest("")

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called")
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
	assert.Equal(s.T(), "application/json", w.Header().Get("Content-Type"))
	assert.JSONEq(s.T(),
		`{"error":"unauthorized","error_description":"Missing or invalid Authorization header"}`,
		w.Body.String(),
	)
}

func (s *AuthMiddlewareTestSuite) TestInvalidAuthorizationFormats() {
	testCases := []struct {
		name       string
		authHeader string
	}{
		{"no bearer prefix", "token-without-bearer"},
		{"wrong prefix", "Basic dXNlcjpwYXNz"},
		{"lowercase bearer", "bearer token"},
		{"bearer without space", "Bearertoken"},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			nextHandler := &mockHandler{}
			middleware := RequireAuth(s.validator, nil, s.logger) // nil for revocation checker
			handler := middleware(nextHandler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tc.authHeader)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.False(s.T(), nextHandler.called, "next handler should not be called")
			assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
			assert.JSONEq(s.T(),
				`{"error":"unauthorized","error_description":"Missing or invalid Authorization header"}`,
				w.Body.String(),
			)
		})
	}
}

func (s *AuthMiddlewareTestSuite) TestBearerWithEmptyToken() {
	s.validator.On("ValidateToken", "").Return(nil, errors.New("empty token"))

	w := s.makeRequest("Bearer ")

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called")
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
	assert.JSONEq(s.T(),
		`{"error":"unauthorized","error_description":"Invalid or expired token"}`,
		w.Body.String(),
	)
}

func (s *AuthMiddlewareTestSuite) TestBearerWithWhitespaceToken() {
	s.validator.On("ValidateToken", "   ").Return(nil, errors.New("invalid token"))

	w := s.makeRequest("Bearer    ")

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called")
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
}

func TestAuthMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMiddlewareTestSuite))
}

// ContextGettersTestSuite tests the context getter functions
type ContextGettersTestSuite struct {
	suite.Suite
}

func (s *ContextGettersTestSuite) TestGetUserID() {
	testCases := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "valid user ID",
			ctx:      context.WithValue(context.Background(), ContextKeyUserID, "user-123"),
			expected: "user-123",
		},
		{
			name:     "missing user ID",
			ctx:      context.Background(),
			expected: "",
		},
		{
			name:     "wrong type (int)",
			ctx:      context.WithValue(context.Background(), ContextKeyUserID, 123),
			expected: "",
		},
		{
			name:     "wrong type (nil)",
			ctx:      context.WithValue(context.Background(), ContextKeyUserID, nil),
			expected: "",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			result := GetUserID(tc.ctx)
			assert.Equal(s.T(), tc.expected, result)
		})
	}
}

func (s *ContextGettersTestSuite) TestGetSessionID() {
	testCases := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "valid session ID",
			ctx:      context.WithValue(context.Background(), ContextKeySessionID, "session-456"),
			expected: "session-456",
		},
		{
			name:     "missing session ID",
			ctx:      context.Background(),
			expected: "",
		},
		{
			name:     "wrong type (int)",
			ctx:      context.WithValue(context.Background(), ContextKeySessionID, 456),
			expected: "",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			result := GetSessionID(tc.ctx)
			assert.Equal(s.T(), tc.expected, result)
		})
	}
}

func (s *ContextGettersTestSuite) TestGetClientID() {
	testCases := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name:     "valid client ID",
			ctx:      context.WithValue(context.Background(), ContextKeyClientID, "client-789"),
			expected: "client-789",
		},
		{
			name:     "missing client ID",
			ctx:      context.Background(),
			expected: "",
		},
		{
			name:     "wrong type (int)",
			ctx:      context.WithValue(context.Background(), ContextKeyClientID, 789),
			expected: "",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			result := GetClientID(tc.ctx)
			assert.Equal(s.T(), tc.expected, result)
		})
	}
}

func TestContextGettersTestSuite(t *testing.T) {
	suite.Run(t, new(ContextGettersTestSuite))
}
