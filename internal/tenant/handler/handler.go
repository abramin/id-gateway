package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"credo/internal/platform/middleware"
	"credo/internal/tenant/models"
	"credo/internal/transport/httputil"
	dErrors "credo/pkg/domain-errors"
)

// Service defines the interface for tenant operations.
// Returns domain objects, not HTTP response DTOs.
type Service interface {
	CreateTenant(ctx context.Context, name string) (*models.Tenant, error)
	GetTenant(ctx context.Context, id uuid.UUID) (*models.TenantDetails, error)
	CreateClient(ctx context.Context, req *models.CreateClientRequest) (*models.Client, string, error)
	GetClient(ctx context.Context, id uuid.UUID) (*models.Client, error)
	UpdateClient(ctx context.Context, id uuid.UUID, req *models.UpdateClientRequest) (*models.Client, string, error)
}

type Handler struct {
	service Service
	logger  *slog.Logger
}

func New(service Service, logger *slog.Logger) *Handler {
	return &Handler{service: service, logger: logger}
}

func (h *Handler) Register(r chi.Router) {
	r.Post("/admin/tenants", h.HandleCreateTenant)
	r.Get("/admin/tenants/{id}", h.HandleGetTenant)
	r.Post("/admin/clients", h.HandleCreateClient)
	r.Get("/admin/clients/{id}", h.HandleGetClient)
	r.Put("/admin/clients/{id}", h.HandleUpdateClient)
}

// HandleCreateTenant creates a tenant.
func (h *Handler) HandleCreateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req *models.CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid json"))
		return
	}

	req.Normalize()
	if err := req.Validate(); err != nil {
		h.logger.WarnContext(ctx, "invalid authorize request",
			"error", err,
			"request_id", requestID,
		)
		httputil.WriteError(w, err)
		return
	}
	tenant, err := h.service.CreateTenant(ctx, req.Name)
	if err != nil {
		h.logger.ErrorContext(ctx, "create tenant failed", "error", err, "request_id", requestID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"tenant_id": tenant.ID, "tenant": tenant})
}

// HandleGetTenant returns tenant metadata with counts.
func (h *Handler) HandleGetTenant(w http.ResponseWriter, r *http.Request) {
	// TODO: 403 if not admin
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)
	idStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid tenant id"))
		return
	}

	res, err := h.service.GetTenant(ctx, tenantID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get tenant failed", "error", err, "request_id", requestID, "tenant_id", tenantID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, res)
}

// HandleCreateClient registers a new client under a tenant.
func (h *Handler) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	var req models.CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid json"))
		return
	}

	client, secret, err := h.service.CreateClient(ctx, &req)
	if err != nil {
		h.logger.ErrorContext(ctx, "create client failed", "error", err, "request_id", requestID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, toClientResponse(client, secret))
}

// HandleGetClient returns client metadata.
func (h *Handler) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	client, err := h.service.GetClient(ctx, clientID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get client failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, ""))
}

// HandleUpdateClient updates metadata and optionally rotates secret.
func (h *Handler) HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := middleware.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := uuid.Parse(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	var req models.UpdateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid json"))
		return
	}

	client, secret, err := h.service.UpdateClient(ctx, clientID, &req)
	if err != nil {
		h.logger.ErrorContext(ctx, "update client failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, secret))
}

// Response mapping functions - convert domain objects to HTTP DTOs

func toClientResponse(client *models.Client, secret string) *models.ClientResponse {
	return &models.ClientResponse{
		ID:            client.ID,
		TenantID:      client.TenantID,
		Name:          client.Name,
		ClientID:      client.ClientID,
		ClientSecret:  secret,
		RedirectURIs:  client.RedirectURIs,
		AllowedGrants: client.AllowedGrants,
		AllowedScopes: client.AllowedScopes,
		Status:        client.Status.String(),
	}
}
