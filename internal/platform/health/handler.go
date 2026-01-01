// Package health provides HTTP health check endpoints for liveness, readiness, and status probes.
package health

import (
	"maps"
	"net/http"
	"sync"
	"time"

	"credo/pkg/platform/httputil"

	"github.com/go-chi/chi/v5"
)

// Version is set at build time via ldflags.
var Version = "dev"

// CheckFunc is a function that checks the health of a dependency.
// It returns nil if healthy, or an error describing the issue.
type CheckFunc func() error

// Handler provides health check endpoints.
type Handler struct {
	startTime   time.Time
	environment string

	mu     sync.RWMutex
	checks map[string]CheckFunc
}

// New creates a new health handler.
func New(environment string) *Handler {
	return &Handler{
		startTime:   time.Now(),
		environment: environment,
		checks:      make(map[string]CheckFunc),
	}
}

// RegisterCheck adds a named health check for the readiness probe.
func (h *Handler) RegisterCheck(name string, check CheckFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

// Register mounts health check routes on the given router.
func (h *Handler) Register(r chi.Router) {
	r.Get("/health", h.HandleStatus)
	r.Get("/health/live", h.HandleLiveness)
	r.Get("/health/ready", h.HandleReadiness)
}

// LivenessResponse is the response for the liveness probe.
type LivenessResponse struct {
	Status string `json:"status"`
}

// HandleLiveness returns a simple liveness probe response.
// This endpoint should always return 200 OK if the service is running.
func (h *Handler) HandleLiveness(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, LivenessResponse{
		Status: "alive",
	})
}

// ReadinessResponse is the response for the readiness probe.
type ReadinessResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

// HandleReadiness returns a readiness probe response.
// This endpoint checks all registered dependencies and returns 503 if any are unhealthy.
func (h *Handler) HandleReadiness(w http.ResponseWriter, _ *http.Request) {
	h.mu.RLock()
	checks := make(map[string]CheckFunc, len(h.checks))
	maps.Copy(checks, h.checks)
	h.mu.RUnlock()

	response := ReadinessResponse{
		Status: "ready",
		Checks: make(map[string]string),
	}

	allHealthy := true
	for name, check := range checks {
		if err := check(); err != nil {
			response.Checks[name] = "down: " + err.Error()
			allHealthy = false
		} else {
			response.Checks[name] = "up"
		}
	}

	if !allHealthy {
		response.Status = "not_ready"
		httputil.WriteJSON(w, http.StatusServiceUnavailable, response)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// StatusResponse is the response for the general health status endpoint.
type StatusResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	Environment   string `json:"environment"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Timestamp     string `json:"timestamp"`
}

// HandleStatus returns general health status with version and uptime information.
func (h *Handler) HandleStatus(w http.ResponseWriter, _ *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, StatusResponse{
		Status:        "healthy",
		Version:       Version,
		Environment:   h.environment,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	})
}
