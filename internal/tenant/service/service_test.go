package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	tenant "credo/internal/tenant/models"

	"credo/internal/tenant/store"
	dErrors "credo/pkg/domain-errors"
)

func TestCreateTenantValidation(t *testing.T) {
	svc := New(store.NewInMemoryTenantStore(), store.NewInMemoryClientStore(), nil)

	if _, err := svc.CreateTenant(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty name")
	}

	longName := make([]byte, 129)
	if _, err := svc.CreateTenant(context.Background(), string(longName)); err == nil {
		t.Fatalf("expected validation error for long name")
	}

	if _, err := svc.CreateTenant(context.Background(), "Acme"); err != nil {
		t.Fatalf("expected tenant creation to succeed: %v", err)
	}
	if _, err := svc.CreateTenant(context.Background(), "acme"); err == nil {
		t.Fatalf("expected conflict for duplicate name")
	}
}

func TestCreateAndGetClient(t *testing.T) {
	tenants := store.NewInMemoryTenantStore()
	clients := store.NewInMemoryClientStore()
	svc := New(tenants, clients, nil)

	tenantRecord, err := svc.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("unexpected error creating tenant: %v", err)
	}

	req := &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	}

	created, err := svc.CreateClient(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	if created.ClientSecret == "" {
		t.Fatalf("expected client secret to be returned for confidential client")
	}

	fetched, err := svc.GetClient(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("unexpected error getting client: %v", err)
	}
	if fetched.Name != req.Name {
		t.Fatalf("expected name %s, got %s", req.Name, fetched.Name)
	}
}

func TestUpdateClient(t *testing.T) {
	tenants := store.NewInMemoryTenantStore()
	clients := store.NewInMemoryClientStore()
	svc := New(tenants, clients, nil)

	tenantRecord, _ := svc.CreateTenant(context.Background(), "Acme")
	created, _ := svc.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})

	newName := "Updated"
	newRedirects := []string{"https://app.example.com/new"}
	resp, err := svc.UpdateClient(context.Background(), created.ID, &tenant.UpdateClientRequest{
		Name:         &newName,
		RedirectURIs: &newRedirects,
		RotateSecret: true,
	})
	if err != nil {
		t.Fatalf("unexpected error updating client: %v", err)
	}
	if resp.Name != newName {
		t.Fatalf("expected updated name")
	}
	if resp.ClientSecret == "" {
		t.Fatalf("expected rotated secret to be returned")
	}
}

func TestGetTenantCounts(t *testing.T) {
	tenants := store.NewInMemoryTenantStore()
	clients := store.NewInMemoryClientStore()
	svc := New(tenants, clients, nil)

	tenantRecord, _ := svc.CreateTenant(context.Background(), "Acme")
	_, _ = svc.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})

	details, err := svc.GetTenant(context.Background(), tenantRecord.ID)
	if err != nil {
		t.Fatalf("unexpected error getting tenant: %v", err)
	}
	if details.ClientCount != 1 {
		t.Fatalf("expected 1 client, got %d", details.ClientCount)
	}
	if details.Tenant.ID != tenantRecord.ID {
		t.Fatalf("unexpected tenant id")
	}
}

func TestValidationErrors(t *testing.T) {
	svc := New(store.NewInMemoryTenantStore(), store.NewInMemoryClientStore(), nil)
	_, err := svc.CreateClient(context.Background(), &tenant.CreateClientRequest{TenantID: uuid.New()})
	if err == nil {
		t.Fatalf("expected validation error for missing fields")
	}

	_, err = svc.UpdateClient(context.Background(), uuid.New(), &tenant.UpdateClientRequest{RedirectURIs: &[]string{"invalid"}})
	if err == nil {
		t.Fatalf("expected validation error for redirect uri")
	}
}

func TestCreateClientHashesSecret(t *testing.T) {
	tenants := store.NewInMemoryTenantStore()
	clients := store.NewInMemoryClientStore()
	svc := New(tenants, clients, nil)

	tenantRecord, _ := svc.CreateTenant(context.Background(), "Acme")
	resp, err := svc.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Fatalf("expected secret for confidential client")
	}

	stored, err := clients.FindByID(context.Background(), resp.ID)
	if err != nil {
		t.Fatalf("failed to find stored client: %v", err)
	}
	if stored.ClientSecretHash == "" {
		t.Fatalf("expected stored client secret hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(stored.ClientSecretHash), []byte(resp.ClientSecret)); err != nil {
		t.Fatalf("stored hash does not match client secret: %v", err)
	}
}

func TestPublicClientValidation(t *testing.T) {
	tenants := store.NewInMemoryTenantStore()
	clients := store.NewInMemoryClientStore()
	svc := New(tenants, clients, nil)

	tenantRecord, _ := svc.CreateTenant(context.Background(), "Acme")
	_, err := svc.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Public",
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []string{"client_credentials"},
		AllowedScopes: []string{"openid"},
		Public:        true,
	})
	if err == nil {
		t.Fatalf("expected validation error for public client with client_credentials grant")
	}
	if !dErrors.Is(err, dErrors.CodeValidation) {
		t.Fatalf("expected validation error code, got %v", err)
	}
}

func TestRedirectURIRequiresHost(t *testing.T) {
	tenants := store.NewInMemoryTenantStore()
	clients := store.NewInMemoryClientStore()
	svc := New(tenants, clients, nil)

	tenantRecord, _ := svc.CreateTenant(context.Background(), "Acme")
	_, err := svc.CreateClient(context.Background(), &tenant.CreateClientRequest{
		TenantID:      tenantRecord.ID,
		Name:          "Web",
		RedirectURIs:  []string{"https:///callback"},
		AllowedGrants: []string{"authorization_code"},
		AllowedScopes: []string{"openid"},
	})
	if err == nil {
		t.Fatalf("expected validation error for redirect without host")
	}
}
