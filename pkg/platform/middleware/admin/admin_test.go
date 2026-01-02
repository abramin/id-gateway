package admin

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

// AdminMiddlewareSuite tests the admin authentication middleware.
//
// Justification: Security-critical authentication middleware.
// The invariant "wrong token never reaches handler" must be preserved.
type AdminMiddlewareSuite struct {
	suite.Suite
	logger *slog.Logger
}

func TestAdminMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(AdminMiddlewareSuite))
}

func (s *AdminMiddlewareSuite) SetupTest() {
	s.logger = slog.Default()
}

func (s *AdminMiddlewareSuite) TestTokenValidation() {
	s.Run("correct token passes to next handler", func() {
		expectedToken := "secret-admin-token"
		handlerCalled := false
		adminAuthorized := false

		handler := RequireAdminToken(expectedToken, s.logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				adminAuthorized = IsAdminRequest(r.Context())
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
		req.Header.Set("X-Admin-Token", expectedToken)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		s.True(handlerCalled, "next handler should be called")
		s.True(adminAuthorized, "admin context should be marked as authorized")
		s.Equal(http.StatusOK, w.Code)
	})

	s.Run("wrong token returns 401 and blocks handler", func() {
		expectedToken := "secret-admin-token"
		handlerCalled := false

		handler := RequireAdminToken(expectedToken, s.logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
		req.Header.Set("X-Admin-Token", "wrong-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		s.False(handlerCalled, "next handler should NOT be called")
		s.Equal(http.StatusUnauthorized, w.Code)
		s.Contains(w.Body.String(), "unauthorized")
	})

	s.Run("missing token returns 401", func() {
		expectedToken := "secret-admin-token"
		handlerCalled := false

		handler := RequireAdminToken(expectedToken, s.logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
		// No X-Admin-Token header
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		s.False(handlerCalled, "next handler should NOT be called")
		s.Equal(http.StatusUnauthorized, w.Code)
	})

	s.Run("empty token returns 401", func() {
		expectedToken := "secret-admin-token"
		handlerCalled := false

		handler := RequireAdminToken(expectedToken, s.logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
		req.Header.Set("X-Admin-Token", "")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		s.False(handlerCalled, "next handler should NOT be called")
		s.Equal(http.StatusUnauthorized, w.Code)
	})
}

func (s *AdminMiddlewareSuite) TestActorIDContextInjection() {
	s.Run("captures X-Admin-Actor-ID in context", func() {
		expectedToken := "secret-admin-token"
		var capturedActorID string

		handler := RequireAdminToken(expectedToken, s.logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedActorID = GetAdminActorID(r.Context())
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
		req.Header.Set("X-Admin-Token", expectedToken)
		req.Header.Set("X-Admin-Actor-ID", "admin-user-123")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		s.Equal("admin-user-123", capturedActorID)
	})

	s.Run("missing actor ID results in empty string", func() {
		expectedToken := "secret-admin-token"
		var capturedActorID string

		handler := RequireAdminToken(expectedToken, s.logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedActorID = GetAdminActorID(r.Context())
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
		req.Header.Set("X-Admin-Token", expectedToken)
		// No X-Admin-Actor-ID header
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		s.Empty(capturedActorID)
	})
}

func (s *AdminMiddlewareSuite) TestGetAdminActorID() {
	s.Run("returns empty for fresh context", func() {
		ctx := context.Background()
		s.Empty(GetAdminActorID(ctx))
	})

	s.Run("returns actor ID from context", func() {
		ctx := context.WithValue(context.Background(), ContextKeyAdminActorID, "test-actor")
		s.Equal("test-actor", GetAdminActorID(ctx))
	})

	s.Run("returns empty for wrong type in context", func() {
		ctx := context.WithValue(context.Background(), ContextKeyAdminActorID, 12345)
		s.Empty(GetAdminActorID(ctx))
	})
}
