package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"credo/pkg/platform/httputil"
	request "credo/pkg/platform/middleware/request"
)

// Handler handles admin monitoring and stats endpoints
type Handler struct {
	service *Service
	logger  *slog.Logger
}

// New creates a new admin handler
func New(service *Service, logger *slog.Logger) *Handler {
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// Register registers admin routes with the router
func (h *Handler) Register(r chi.Router) {
	r.Get("/admin/stats", h.HandleGetStats)
	r.Get("/admin/users", h.HandleGetAllUsers)
	r.Get("/admin/audit/recent", h.HandleGetRecentAuditEvents)
}

// HandleGetStats returns overall system statistics
func (h *Handler) HandleGetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	stats, err := h.service.GetStats(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get stats",
			"error", err,
			"request_id", requestID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to get stats"})
		return
	}

	h.logger.InfoContext(ctx, "admin stats retrieved",
		"request_id", requestID,
	)

	httputil.WriteJSON(w, http.StatusOK, stats)
}

// HandleGetAllUsers returns all users with session information
func (h *Handler) HandleGetAllUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	users, err := h.service.GetAllUsers(ctx)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get users",
			"error", err,
			"request_id", requestID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to get users"})
		return
	}

	h.logger.InfoContext(ctx, "admin users list retrieved",
		"request_id", requestID,
		"count", len(users),
	)

	httputil.WriteJSON(w, http.StatusOK, toUsersListResponse(users))
}

// HandleGetRecentAuditEvents returns recent audit events
func (h *Handler) HandleGetRecentAuditEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	// Parse limit from query parameter, default to 50
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	events, err := h.service.GetRecentAuditEvents(ctx, limit)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to get recent audit events",
			"error", err,
			"request_id", requestID,
		)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to get audit events"})
		return
	}

	h.logger.InfoContext(ctx, "admin audit events retrieved",
		"request_id", requestID,
		"count", len(events),
	)

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
}

// Response mapping functions - convert domain objects to HTTP DTOs

func toUsersListResponse(users []*UserInfo) *UsersListResponse {
	responses := make([]*UserInfoResponse, len(users))
	for i, u := range users {
		responses[i] = toUserInfoResponse(u)
	}
	return &UsersListResponse{
		Users: responses,
		Total: len(responses),
	}
}

func toUserInfoResponse(u *UserInfo) *UserInfoResponse {
	return &UserInfoResponse{
		ID:           u.ID.String(),
		Email:        u.Email,
		FirstName:    u.FirstName,
		LastName:     u.LastName,
		SessionCount: u.SessionCount,
		LastActive:   u.LastActive,
		Verified:     u.Verified,
	}
}
