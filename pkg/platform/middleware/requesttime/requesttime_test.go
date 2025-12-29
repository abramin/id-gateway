package requesttime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"credo/pkg/requestcontext"
)

func TestMiddleware_SetsTimeInContext(t *testing.T) {
	var capturedTime time.Time
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTime = requestcontext.Now(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	before := time.Now()
	handler.ServeHTTP(w, req)
	after := time.Now()

	assert.False(t, capturedTime.IsZero())
	assert.True(t, !capturedTime.Before(before), "captured time should be >= before")
	assert.True(t, !capturedTime.After(after), "captured time should be <= after")
}

func TestMiddleware_TimeIsConsistentWithinRequest(t *testing.T) {
	var firstRead, secondRead time.Time
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstRead = requestcontext.Now(r.Context())
		time.Sleep(10 * time.Millisecond)
		secondRead = requestcontext.Now(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, firstRead, secondRead, "time should be consistent within request")
}

func TestNow_FallbackToRealTime(t *testing.T) {
	ctx := context.Background() // No middleware

	before := time.Now()
	result := requestcontext.Now(ctx)
	after := time.Now()

	assert.True(t, !result.Before(before), "result should be >= before")
	assert.True(t, !result.After(after), "result should be <= after")
}

func TestWithTime_InjectsFixedTime(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	ctx := requestcontext.WithTime(context.Background(), fixedTime)

	assert.Equal(t, fixedTime, requestcontext.Now(ctx))
}

func TestWithTime_OverridesExistingTime(t *testing.T) {
	originalTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	ctx := requestcontext.WithTime(context.Background(), originalTime)
	ctx = requestcontext.WithTime(ctx, newTime)

	assert.Equal(t, newTime, requestcontext.Now(ctx))
}
