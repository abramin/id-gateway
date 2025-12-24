package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"credo/internal/tenant/models"
	"credo/internal/tenant/service"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/httputil"
	request "credo/pkg/platform/middleware/request"
)

// Service defines the interface for tenant operations.
// Returns domain objects, not HTTP response DTOs.
//
// Authorization Model (PRD-026A):
// - Platform admins can access any tenant/client (use GetClient, UpdateClient)
// - Tenant admins can only access their own tenant's clients (use GetClientForTenant, UpdateClientForTenant)
// - Currently only platform admin auth is implemented (shared X-Admin-Token)
// - When tenant admin auth is added, handlers must extract tenant context and use scoped methods
type Service interface {
	CreateTenant(ctx context.Context, name string) (*models.Tenant, error)
	GetTenant(ctx context.Context, id id.TenantID) (*models.TenantDetails, error)
	DeactivateTenant(ctx context.Context, id id.TenantID) (*models.Tenant, error)
	ReactivateTenant(ctx context.Context, id id.TenantID) (*models.Tenant, error)
	CreateClient(ctx context.Context, cmd *service.CreateClientCommand) (*models.Client, string, error)
	GetClient(ctx context.Context, id id.ClientID) (*models.Client, error)
	GetClientForTenant(ctx context.Context, tenantID id.TenantID, id id.ClientID) (*models.Client, error)
	UpdateClient(ctx context.Context, id id.ClientID, cmd *service.UpdateClientCommand) (*models.Client, string, error)
	UpdateClientForTenant(ctx context.Context, tenantID id.TenantID, id id.ClientID, cmd *service.UpdateClientCommand) (*models.Client, string, error)
	DeactivateClient(ctx context.Context, id id.ClientID) (*models.Client, error)
	ReactivateClient(ctx context.Context, id id.ClientID) (*models.Client, error)
	RotateClientSecret(ctx context.Context, id id.ClientID) (*models.Client, string, error)
	RotateClientSecretForTenant(ctx context.Context, tenantID id.TenantID, id id.ClientID) (*models.Client, string, error)
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
	r.Post("/admin/tenants/{id}/deactivate", h.HandleDeactivateTenant)
	r.Post("/admin/tenants/{id}/reactivate", h.HandleReactivateTenant)
	r.Post("/admin/clients", h.HandleCreateClient)
	r.Get("/admin/clients/{id}", h.HandleGetClient)
	r.Put("/admin/clients/{id}", h.HandleUpdateClient)
	r.Post("/admin/clients/{id}/deactivate", h.HandleDeactivateClient)
	r.Post("/admin/clients/{id}/reactivate", h.HandleReactivateClient)
	r.Post("/admin/clients/{id}/rotate-secret", h.HandleRotateClientSecret)
}

// HandleCreateTenant creates a tenant.
func (h *Handler) HandleCreateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	req, ok := httputil.DecodeAndPrepare[CreateTenantRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	tenant, err := h.service.CreateTenant(ctx, req.Name)
	if err != nil {
		h.logger.ErrorContext(ctx, "create tenant failed", "error", err, "request_id", requestID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, &TenantCreateResponse{
		TenantID: tenant.ID.String(),
		Tenant:   toTenantResponse(tenant),
	})
}

// HandleGetTenant returns tenant metadata with counts.
// PRD-026A FR-2: Requires admin authorization. Currently uses X-Admin-Token middleware.
// TODO: When tenant admin auth is implemented, verify caller has access to this tenant.
func (h *Handler) HandleGetTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	idStr := chi.URLParam(r, "id")
	tenantID, err := id.ParseTenantID(idStr)
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

	httputil.WriteJSON(w, http.StatusOK, toTenantDetailsResponse(res))
}

// HandleDeactivateTenant deactivates a tenant.
// PRD-026B FR-1: Deactivated tenants block OAuth flows for all clients under them.
func (h *Handler) HandleDeactivateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	idStr := chi.URLParam(r, "id")
	tenantID, err := id.ParseTenantID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid tenant id"))
		return
	}

	tenant, err := h.service.DeactivateTenant(ctx, tenantID)
	if err != nil {
		h.logger.ErrorContext(ctx, "deactivate tenant failed", "error", err, "request_id", requestID, "tenant_id", tenantID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toTenantResponse(tenant))
}

// HandleReactivateTenant reactivates a tenant.
// PRD-026B FR-2: Reactivated tenants restore OAuth flows for their clients.
func (h *Handler) HandleReactivateTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)
	idStr := chi.URLParam(r, "id")
	tenantID, err := id.ParseTenantID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid tenant id"))
		return
	}

	tenant, err := h.service.ReactivateTenant(ctx, tenantID)
	if err != nil {
		h.logger.ErrorContext(ctx, "reactivate tenant failed", "error", err, "request_id", requestID, "tenant_id", tenantID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toTenantResponse(tenant))
}

// HandleCreateClient registers a new client under a tenant.
func (h *Handler) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	req, ok := httputil.DecodeAndPrepare[CreateClientRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	cmd, err := req.ToCommand()
	if err != nil {
		httputil.WriteError(w, err)
		return
	}

	client, secret, err := h.service.CreateClient(ctx, cmd)
	if err != nil {
		h.logger.ErrorContext(ctx, "create client failed", "error", err, "request_id", requestID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, toClientResponse(client, secret))
}

// HandleGetClient returns client metadata.
// PRD-026A FR-4: Currently uses platform admin auth (X-Admin-Token).
// TODO: When tenant admin auth is implemented:
//  1. Extract tenant context from auth token
//  2. Use h.service.GetClientForTenant(ctx, tenantID, clientID) instead
//  3. This enforces tenant isolation at the service layer (per PRD-026A §Tenant Boundary)
func (h *Handler) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := id.ParseClientID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	// Platform admin: can access any client
	// When tenant admin auth is added, use GetClientForTenant instead
	client, err := h.service.GetClient(ctx, clientID)
	if err != nil {
		h.logger.ErrorContext(ctx, "get client failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, ""))
}

// HandleUpdateClient updates metadata and optionally rotates secret.
// PRD-026A FR-4: Currently uses platform admin auth (X-Admin-Token).
// TODO: When tenant admin auth is implemented:
//  1. Extract tenant context from auth token
//  2. Use h.service.UpdateClientForTenant(ctx, tenantID, clientID, req) instead
//  3. This enforces tenant isolation at the service layer (per PRD-026A §Tenant Boundary)
func (h *Handler) HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := id.ParseClientID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	req, ok := httputil.DecodeAndPrepare[UpdateClientRequest](w, r, h.logger, ctx, requestID)
	if !ok {
		return
	}

	cmd := req.ToCommand()

	// Platform admin: can update any client
	// When tenant admin auth is added, use UpdateClientForTenant instead
	client, secret, err := h.service.UpdateClient(ctx, clientID, cmd)
	if err != nil {
		h.logger.ErrorContext(ctx, "update client failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, secret))
}

// HandleDeactivateClient deactivates a client.
// PRD-026B FR-3: Deactivated clients block OAuth flows.
func (h *Handler) HandleDeactivateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := id.ParseClientID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	client, err := h.service.DeactivateClient(ctx, clientID)
	if err != nil {
		h.logger.ErrorContext(ctx, "deactivate client failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, ""))
}

// HandleReactivateClient reactivates a client.
// PRD-026B FR-4: Reactivated clients restore OAuth flows.
func (h *Handler) HandleReactivateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := id.ParseClientID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	client, err := h.service.ReactivateClient(ctx, clientID)
	if err != nil {
		h.logger.ErrorContext(ctx, "reactivate client failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, ""))
}

// HandleRotateClientSecret rotates the client secret for a confidential client.
// Returns the new secret (only available at rotation time).
// PRD-026A FR-4: Currently uses platform admin auth (X-Admin-Token).
func (h *Handler) HandleRotateClientSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := request.GetRequestID(ctx)

	idStr := chi.URLParam(r, "id")
	clientID, err := id.ParseClientID(idStr)
	if err != nil {
		httputil.WriteError(w, dErrors.New(dErrors.CodeBadRequest, "invalid client id"))
		return
	}

	client, secret, err := h.service.RotateClientSecret(ctx, clientID)
	if err != nil {
		h.logger.ErrorContext(ctx, "rotate client secret failed", "error", err, "request_id", requestID, "client_id", clientID)
		httputil.WriteError(w, err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, toClientResponse(client, secret))
}

// Response mapping functions - convert domain objects to HTTP DTOs

func toTenantResponse(t *models.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:        t.ID.String(),
		Name:      t.Name,
		Status:    t.Status,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

func toTenantDetailsResponse(td *models.TenantDetails) *TenantDetailsResponse {
	return &TenantDetailsResponse{
		ID:          td.ID.String(),
		Name:        td.Name,
		Status:      td.Status,
		CreatedAt:   td.CreatedAt,
		UpdatedAt:   td.UpdatedAt,
		UserCount:   td.UserCount,
		ClientCount: td.ClientCount,
	}
}

func toClientResponse(client *models.Client, secret string) *ClientResponse {
	return &ClientResponse{
		ID:            client.ID.String(),
		TenantID:      client.TenantID.String(),
		Name:          client.Name,
		OAuthClientID: client.OAuthClientID,
		ClientSecret:  secret, // Empty string omitted due to omitempty tag
		RedirectURIs:  client.RedirectURIs,
		AllowedGrants: client.AllowedGrants,
		AllowedScopes: client.AllowedScopes,
		Status:        client.Status.String(),
		PublicClient:  !client.IsConfidential(),
	}
}
