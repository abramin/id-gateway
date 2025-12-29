package auth

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

	id "credo/pkg/domain"
	"credo/pkg/requestcontext"
)

// Test UUIDs for consistent testing
const (
	testUserID    = "550e8400-e29b-41d4-a716-446655440001"
	testSessionID = "550e8400-e29b-41d4-a716-446655440002"
	testClientID  = "550e8400-e29b-41d4-a716-446655440003"
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
		UserID:    testUserID,
		SessionID: testSessionID,
		ClientID:  testClientID,
		JTI:       "jti-123",
	}
	s.validator.On("ValidateToken", "valid-token").Return(expectedClaims, nil)

	w := s.makeRequest("Bearer valid-token")

	require.True(s.T(), s.nextHandler.called, "next handler should be called")
	assert.Equal(s.T(), http.StatusOK, w.Code)

	// Verify context values were set correctly as typed IDs
	assert.Equal(s.T(), testUserID, requestcontext.UserID(s.nextHandler.context).String())
	assert.Equal(s.T(), testSessionID, requestcontext.SessionID(s.nextHandler.context).String())
	assert.Equal(s.T(), testClientID, requestcontext.ClientID(s.nextHandler.context).String())
}

func (s *AuthMiddlewareTestSuite) TestRevokedToken() {
	expectedClaims := &JWTClaims{
		UserID:    testUserID,
		SessionID: testSessionID,
		ClientID:  testClientID,
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

func (s *AuthMiddlewareTestSuite) TestRevocationCheckMissingJTI() {
	expectedClaims := &JWTClaims{
		UserID:    testUserID,
		SessionID: testSessionID,
		ClientID:  testClientID,
	}
	s.validator.On("ValidateToken", "valid-token").Return(expectedClaims, nil)

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

func (s *AuthMiddlewareTestSuite) TestRevocationCheckError() {
	expectedClaims := &JWTClaims{
		UserID:    testUserID,
		SessionID: testSessionID,
		ClientID:  testClientID,
		JTI:       "jti-123",
	}
	s.validator.On("ValidateToken", "valid-token").Return(expectedClaims, nil)
	s.revoker.On("IsTokenRevoked", mock.Anything, "jti-123").Return(false, errors.New("db down"))

	handler := RequireAuth(s.validator, s.revoker, s.logger)(s.nextHandler)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called")
	assert.Equal(s.T(), http.StatusInternalServerError, w.Code)
	assert.JSONEq(s.T(),
		`{"error":"internal_error","error_description":"Failed to validate token"}`,
		w.Body.String(),
	)
}

func (s *AuthMiddlewareTestSuite) TestMalformedUserIDInClaims() {
	expectedClaims := &JWTClaims{
		UserID:    "not-a-valid-uuid",
		SessionID: testSessionID,
		ClientID:  testClientID,
		JTI:       "jti-123",
	}
	s.validator.On("ValidateToken", "valid-token").Return(expectedClaims, nil)

	w := s.makeRequest("Bearer valid-token")

	assert.False(s.T(), s.nextHandler.called, "next handler should not be called for malformed claims")
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
	assert.JSONEq(s.T(),
		`{"error":"unauthorized","error_description":"Invalid or expired token"}`,
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

// ContextGettersTestSuite tests the context getter functions via requestcontext
type ContextGettersTestSuite struct {
	suite.Suite
}

func (s *ContextGettersTestSuite) TestUserID() {
	parsedUserID, _ := id.ParseUserID(testUserID)

	s.Run("valid user ID", func() {
		ctx := requestcontext.WithUserID(context.Background(), parsedUserID)
		result := requestcontext.UserID(ctx)
		assert.Equal(s.T(), testUserID, result.String())
	})

	s.Run("missing user ID", func() {
		ctx := context.Background()
		result := requestcontext.UserID(ctx)
		assert.True(s.T(), result.IsNil())
	})
}

func (s *ContextGettersTestSuite) TestSessionID() {
	parsedSessionID, _ := id.ParseSessionID(testSessionID)

	s.Run("valid session ID", func() {
		ctx := requestcontext.WithSessionID(context.Background(), parsedSessionID)
		result := requestcontext.SessionID(ctx)
		assert.Equal(s.T(), testSessionID, result.String())
	})

	s.Run("missing session ID", func() {
		ctx := context.Background()
		result := requestcontext.SessionID(ctx)
		assert.True(s.T(), result.IsNil())
	})
}

func (s *ContextGettersTestSuite) TestClientID() {
	parsedClientID, _ := id.ParseClientID(testClientID)

	s.Run("valid client ID", func() {
		ctx := requestcontext.WithClientID(context.Background(), parsedClientID)
		result := requestcontext.ClientID(ctx)
		assert.Equal(s.T(), testClientID, result.String())
	})

	s.Run("missing client ID", func() {
		ctx := context.Background()
		result := requestcontext.ClientID(ctx)
		assert.True(s.T(), result.IsNil())
	})
}

func TestContextGettersTestSuite(t *testing.T) {
	suite.Run(t, new(ContextGettersTestSuite))
}
