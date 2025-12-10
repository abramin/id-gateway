package handler

import (
	"context"
	"credo/internal/evidence/registry/models"
)

// RegistryService defines the interface for registry operations used by handlers
type RegistryService interface {
	Citizen(ctx context.Context, nationalID string) (*models.CitizenRecord, error)
	Sanctions(ctx context.Context, nationalID string) (*models.SanctionsRecord, error)
	Check(ctx context.Context, nationalID string) (*models.RegistryResult, error)
}

type Handler struct {
	registryService RegistryService
}

func NewHandler(registryService RegistryService) *Handler {
	return &Handler{registryService: registryService}
}

// func (h *Handler) handleRegistryCitizen(w http.ResponseWriter, r *http.Request) {
// 	h.notImplemented(w, "/registry/citizen")
// }

// func (h *Handler) handleRegistrySanctions(w http.ResponseWriter, r *http.Request) {
// 	h.notImplemented(w, "/registry/sanctions")
// }
