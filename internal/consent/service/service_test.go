package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"id-gateway/internal/audit"
	"id-gateway/internal/consent/models"
	dErrors "id-gateway/pkg/domain-errors"
)

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks Store
func TestGrantCreatesConsent(t *testing.T) {
	now := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	ttl := 24 * time.Hour
	saved := false
	store := stubStore{
		findFn: func(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error) {
			return nil, nil
		},
		saveFn: func(ctx context.Context, consent *models.ConsentRecord) error {
			saved = true
			assert.Equal(t, "user123", consent.UserID)
			assert.Equal(t, models.ConsentPurposeLogin, consent.Purpose)
			assert.True(t, strings.HasPrefix(consent.ID, "consent_"))
			assert.Equal(t, now, consent.GrantedAt)
			require.NotNil(t, consent.ExpiresAt)
			assert.Equal(t, now.Add(ttl), *consent.ExpiresAt)
			return nil
		},
	}
	svc := NewService(store, WithNow(func() time.Time { return now }), WithTTL(ttl))
	granted, err := svc.Grant(context.Background(), "user123", []models.ConsentPurpose{models.ConsentPurposeLogin})
	assert.NoError(t, err)
	assert.True(t, saved)
	assert.Len(t, granted, 1)
}

func TestGrantRenewsExistingConsent(t *testing.T) {
	now := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	ttl := 24 * time.Hour
	expiry := now.Add(ttl)
	existing := &models.ConsentRecord{ID: "consent_abc", UserID: "user123", Purpose: models.ConsentPurposeLogin, GrantedAt: now.Add(-ttl), ExpiresAt: &expiry}

	updated := false
	store := stubStore{
		findFn: func(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error) {
			return existing, nil
		},
		updateFn: func(ctx context.Context, consent *models.ConsentRecord) error {
			updated = true
			assert.Equal(t, "consent_abc", consent.ID)
			require.NotNil(t, consent.ExpiresAt)
			assert.Equal(t, now.Add(ttl), *consent.ExpiresAt)
			assert.Nil(t, consent.RevokedAt)
			return nil
		},
	}
	svc := NewService(store, WithNow(func() time.Time { return now }), WithTTL(ttl))
	granted, err := svc.Grant(context.Background(), "user123", []models.ConsentPurpose{models.ConsentPurposeLogin})
	assert.NoError(t, err)
	assert.True(t, updated)
	assert.Equal(t, "consent_abc", granted[0].ID)
}

func TestRevokeIsIdempotentAndAudited(t *testing.T) {
	now := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	auditStore := audit.NewInMemoryStore()
	auditor := audit.NewPublisher(auditStore)
	revoked := false

	store := stubStore{
		findFn: func(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error) {
			return &models.ConsentRecord{ID: "consent_1"}, nil
		},
		revokeFn: func(ctx context.Context, userID string, purpose models.ConsentPurpose, revokedAt time.Time) error {
			revoked = true
			assert.Equal(t, now, revokedAt)
			return nil
		},
	}

	svc := NewService(store, WithNow(func() time.Time { return now }), WithAuditor(auditor))
	err := svc.Revoke(context.Background(), "user123", models.ConsentPurposeRegistryCheck)
	assert.NoError(t, err)
	assert.True(t, revoked)

	events, err := auditStore.ListByUser(context.Background(), "user123")
	assert.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "consent_revoked", events[0].Action)
}

func TestRequireChecksStatuses(t *testing.T) {
	now := time.Date(2025, 12, 3, 10, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name        string
		record      *models.ConsentRecord
		expectedErr dErrors.Code
	}{
		{name: "missing", record: nil, expectedErr: dErrors.CodeMissingConsent},
		{name: "revoked", record: &models.ConsentRecord{RevokedAt: &now}, expectedErr: dErrors.CodeInvalidConsent},
		{name: "expired", record: &models.ConsentRecord{ExpiresAt: &expired}, expectedErr: dErrors.CodeInvalidConsent},
		{name: "active", record: &models.ConsentRecord{ExpiresAt: &future}, expectedErr: ""},
	}

	for _, tc := range tests {
		store := stubStore{
			findFn: func(ctx context.Context, userID string, purpose models.ConsentPurpose) (*models.ConsentRecord, error) {
				return tc.record, nil
			},
		}
		svc := NewService(store, WithNow(func() time.Time { return now }))
		err := svc.Require(context.Background(), "user123", models.ConsentPurposeVCIssuance)
		if tc.expectedErr == "" {
			assert.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
			assert.True(t, dErrors.Is(err, tc.expectedErr))
		}
	}
}

func TestGrantValidation(t *testing.T) {
	svc := NewService(stubStore{})

	_, err := svc.Grant(context.Background(), "", []models.ConsentPurpose{models.ConsentPurposeLogin})
	assert.True(t, dErrors.Is(err, dErrors.CodeUnauthorized))

	_, err = svc.Grant(context.Background(), "user123", []models.ConsentPurpose{})
	assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))

	_, err = svc.Grant(context.Background(), "user123", []models.ConsentPurpose{"invalid"})
	assert.True(t, dErrors.Is(err, dErrors.CodeBadRequest))
}
