package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/store"
	id "credo/pkg/domain"
	dErrors "credo/pkg/domain-errors"
	"credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/compliance"
	auditmemory "credo/pkg/platform/audit/store/memory"
)

// stubCache is a test double for the cache store
type stubCache struct {
	citizenRecords    map[string]*models.CitizenRecord
	sanctionRecords   map[string]*models.SanctionsRecord
	findCitizenErr    error
	findSanctionErr   error
	saveCitizenErr    error
	saveSanctionErr   error
	saveCitizenCalls  []*models.CitizenRecord
	saveSanctionCalls []*models.SanctionsRecord
	regulatedMode     map[string]bool // track regulated mode per record
}

func newStubCache() *stubCache {
	return &stubCache{
		citizenRecords:  make(map[string]*models.CitizenRecord),
		sanctionRecords: make(map[string]*models.SanctionsRecord),
		regulatedMode:   make(map[string]bool),
	}
}

func (c *stubCache) FindCitizen(_ context.Context, nationalID id.NationalID, regulated bool) (*models.CitizenRecord, error) {
	if c.findCitizenErr != nil {
		return nil, c.findCitizenErr
	}
	if r, ok := c.citizenRecords[nationalID.String()]; ok {
		// Check if regulated mode matches
		if storedRegulated, exists := c.regulatedMode[nationalID.String()]; exists && storedRegulated != regulated {
			return nil, store.ErrNotFound
		}
		return r, nil
	}
	return nil, store.ErrNotFound
}

func (c *stubCache) SaveCitizen(_ context.Context, key id.NationalID, record *models.CitizenRecord, regulated bool) error {
	c.saveCitizenCalls = append(c.saveCitizenCalls, record)
	if c.saveCitizenErr != nil {
		return c.saveCitizenErr
	}
	// Use the key parameter (not record.NationalID) to avoid collision for minimized records
	c.citizenRecords[key.String()] = record
	c.regulatedMode[key.String()] = regulated
	return nil
}

func (c *stubCache) FindSanction(_ context.Context, nationalID id.NationalID) (*models.SanctionsRecord, error) {
	if c.findSanctionErr != nil {
		return nil, c.findSanctionErr
	}
	if r, ok := c.sanctionRecords[nationalID.String()]; ok {
		return r, nil
	}
	return nil, store.ErrNotFound
}

func (c *stubCache) SaveSanction(_ context.Context, key id.NationalID, record *models.SanctionsRecord) error {
	c.saveSanctionCalls = append(c.saveSanctionCalls, record)
	if c.saveSanctionErr != nil {
		return c.saveSanctionErr
	}
	c.sanctionRecords[key.String()] = record
	return nil
}

// stubConsentPort is a test double for consent checks
type stubConsentPort struct {
	err error
}

func (c *stubConsentPort) RequireConsent(_ context.Context, _ id.UserID, _ id.ConsentPurpose) error {
	return c.err
}

// stubProvider is a test double for providers.Provider
type stubProvider struct {
	id       string
	provType providers.ProviderType
	lookupFn func(ctx context.Context, filters map[string]string) (*providers.Evidence, error)
	called   bool
}

func (p *stubProvider) ID() string { return p.id }

func (p *stubProvider) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Protocol: providers.ProtocolHTTP,
		Type:     p.provType,
	}
}

func (p *stubProvider) Lookup(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
	p.called = true
	if p.lookupFn != nil {
		return p.lookupFn(ctx, filters)
	}
	return nil, nil
}

func (p *stubProvider) Health(_ context.Context) error { return nil }

type ServiceSuite struct {
	suite.Suite
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

// Helper to create evidence from domain models
func citizenEvidence(r *models.CitizenRecord) *providers.Evidence {
	return &providers.Evidence{
		ProviderID:   "test-citizen",
		ProviderType: providers.ProviderTypeCitizen,
		Confidence:   1.0,
		Data: map[string]any{
			"national_id":   r.NationalID,
			"full_name":     r.FullName,
			"date_of_birth": r.DateOfBirth,
			"address":       r.Address,
			"valid":         r.Valid,
		},
		CheckedAt: r.CheckedAt,
	}
}

func sanctionsEvidence(r *models.SanctionsRecord) *providers.Evidence {
	return &providers.Evidence{
		ProviderID:   "test-sanctions",
		ProviderType: providers.ProviderTypeSanctions,
		Confidence:   1.0,
		Data: map[string]any{
			"national_id": r.NationalID,
			"listed":      r.Listed,
			"source":      r.Source,
		},
		CheckedAt: r.CheckedAt,
	}
}

// newTestOrchestrator creates an orchestrator with the given stub providers
func newTestOrchestrator(citizenProv, sanctionsProv *stubProvider) *orchestrator.Orchestrator {
	registry := providers.NewProviderRegistry()
	if citizenProv != nil {
		_ = registry.Register(citizenProv)
	}
	if sanctionsProv != nil {
		_ = registry.Register(sanctionsProv)
	}
	return orchestrator.New(orchestrator.OrchestratorConfig{
		Registry:        registry,
		DefaultStrategy: orchestrator.StrategyFallback,
		DefaultTimeout:  5 * time.Second,
	})
}

// Helper to create test IDs
func testUserID() id.UserID {
	userID, _ := id.ParseUserID("550e8400-e29b-41d4-a716-446655440000")
	return userID
}

func testNationalID(s string) id.NationalID {
	nid, _ := id.ParseNationalID(s)
	return nid
}

func (s *ServiceSuite) TestCheckTransactionSemantics() {
	ctx := context.Background()
	nationalIDStr := "ABC123456"
	nationalID := testNationalID(nationalIDStr)
	userID := testUserID()
	now := time.Now()

	citizenRecord := &models.CitizenRecord{
		NationalID:  nationalIDStr,
		FullName:    "Test User",
		DateOfBirth: "1990-01-01",
		Address:     "123 Test St",
		Valid:       true,
		CheckedAt:   now,
	}

	sanctionsRecord := &models.SanctionsRecord{
		NationalID: nationalIDStr,
		Listed:     false,
		Source:     "test-source",
		CheckedAt:  now,
	}

	s.Run("caches both records only when both lookups succeed", func() {
		cache := newStubCache()
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord.NationalID, result.Citizen.NationalID)
		s.Equal(citizenRecord.Valid, result.Citizen.Valid)
		s.Equal(sanctionsRecord.NationalID, result.Sanction.NationalID)
		s.Equal(sanctionsRecord.Listed, result.Sanction.Listed)

		// Both should be cached
		s.Len(cache.saveCitizenCalls, 1)
		s.Len(cache.saveSanctionCalls, 1)
	})

	s.Run("does not cache citizen when sanctions lookup fails", func() {
		cache := newStubCache()
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return nil, providers.NewProviderError(
					providers.ErrorTimeout,
					"test-sanctions",
					"timeout",
					nil,
				)
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().Error(err)
		s.Nil(result)

		// CRITICAL: Neither should be cached (atomic rollback)
		s.Len(cache.saveCitizenCalls, 0)
		s.Len(cache.saveSanctionCalls, 0)
	})

	s.Run("does not cache sanctions when citizen lookup fails", func() {
		cache := newStubCache()
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return nil, providers.NewProviderError(
					providers.ErrorNotFound,
					"test-citizen",
					"not found",
					nil,
				)
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().Error(err)
		s.Nil(result)

		// CRITICAL: Neither should be cached
		s.Len(cache.saveCitizenCalls, 0)
		s.Len(cache.saveSanctionCalls, 0)
	})

	s.Run("uses cached citizen but fetches sanctions when only citizen is cached", func() {
		cache := newStubCache()
		cache.citizenRecords[nationalIDStr] = citizenRecord

		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord.NationalID, result.Sanction.NationalID)

		// Citizen provider should NOT be called (cache hit)
		s.False(citizenProv.called)

		// Only sanctions should be cached (citizen was already cached)
		s.Len(cache.saveCitizenCalls, 0)
		s.Len(cache.saveSanctionCalls, 1)
	})

	s.Run("uses cached sanctions but fetches citizen when only sanctions is cached", func() {
		cache := newStubCache()
		cache.sanctionRecords[nationalIDStr] = sanctionsRecord

		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord.NationalID, result.Citizen.NationalID)
		s.Equal(sanctionsRecord, result.Sanction)

		// Sanctions provider should NOT be called (cache hit)
		s.False(sanctionsProv.called)

		// Only citizen should be cached (sanctions was already cached)
		s.Len(cache.saveCitizenCalls, 1)
		s.Len(cache.saveSanctionCalls, 0)
	})

	s.Run("returns both cached records without provider calls when fully cached", func() {
		cache := newStubCache()
		cache.citizenRecords[nationalIDStr] = citizenRecord
		cache.sanctionRecords[nationalIDStr] = sanctionsRecord

		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord, result.Sanction)

		// No provider calls expected (both cached)
		s.False(citizenProv.called)
		s.False(sanctionsProv.called)

		// No cache saves expected (both already cached)
		s.Len(cache.saveCitizenCalls, 0)
		s.Len(cache.saveSanctionCalls, 0)
	})
}

func (s *ServiceSuite) TestSanctionsErrorMapping() {
	ctx := context.Background()
	userID := testUserID()
	nationalID := testNationalID("SANCT123")

	cases := []struct {
		name     string
		category providers.ErrorCategory
		code     dErrors.Code
	}{
		{
			name:     "timeout maps to CodeTimeout",
			category: providers.ErrorTimeout,
			code:     dErrors.CodeTimeout,
		},
		{
			name:     "not_found maps to CodeNotFound",
			category: providers.ErrorNotFound,
			code:     dErrors.CodeNotFound,
		},
		{
			name:     "provider_outage maps to CodeInternal",
			category: providers.ErrorProviderOutage,
			code:     dErrors.CodeInternal,
		},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			sanctionsProv := &stubProvider{
				id:       "test-sanctions",
				provType: providers.ProviderTypeSanctions,
				lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					return nil, providers.NewProviderError(tc.category, "test-sanctions", "test error", nil)
				},
			}

			orch := newTestOrchestrator(nil, sanctionsProv)
			svc := New(orch, newStubCache(), nil, false)

			result, err := svc.Sanctions(ctx, userID, nationalID)
			s.Require().Error(err)
			s.Nil(result)
			s.True(dErrors.HasCode(err, tc.code), "expected code %s, got %v", tc.code, err)
		})
	}
}

func (s *ServiceSuite) TestCitizenMinimization() {
	ctx := context.Background()
	nationalIDStr := "ABC123456"
	nationalID := testNationalID(nationalIDStr)
	userID := testUserID()
	now := time.Now()

	citizenRecord := &models.CitizenRecord{
		NationalID:  nationalIDStr,
		FullName:    "Test User",
		DateOfBirth: "1990-01-01",
		Address:     "123 Test St",
		Valid:       true,
		CheckedAt:   now,
	}

	s.Run("minimizes citizen record in regulated mode", func() {
		cache := newStubCache()
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, nil)
		svc := New(orch, cache, nil, true) // regulated = true

		result, err := svc.Citizen(ctx, userID, nationalID)
		s.Require().NoError(err)

		// PII fields should be cleared
		s.Equal("", result.NationalID)
		s.Equal("", result.FullName)
		s.Equal("", result.DateOfBirth)
		s.Equal("", result.Address)

		// Valid and CheckedAt should be preserved
		s.True(result.Valid)
		s.Equal(now, result.CheckedAt)
	})

	s.Run("returns full citizen record in non-regulated mode", func() {
		cache := newStubCache()
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, nil)
		svc := New(orch, cache, nil, false) // regulated = false

		result, err := svc.Citizen(ctx, userID, nationalID)
		s.Require().NoError(err)

		// All fields should be present
		s.Equal(nationalIDStr, result.NationalID)
		s.Equal("Test User", result.FullName)
		s.Equal("1990-01-01", result.DateOfBirth)
		s.Equal("123 Test St", result.Address)
		s.True(result.Valid)
	})
}

func (s *ServiceSuite) TestCitizenWithDetailsNoMinimizationNoCache() {
	ctx := context.Background()
	nationalIDStr := "ABC123456"
	nationalID := testNationalID(nationalIDStr)
	userID := testUserID()
	now := time.Now()

	citizenRecord := &models.CitizenRecord{
		NationalID:  nationalIDStr,
		FullName:    "Test User",
		DateOfBirth: "1990-01-01",
		Address:     "123 Test St",
		Valid:       true,
		CheckedAt:   now,
	}

	cache := newStubCache()
	citizenProv := &stubProvider{
		id:       "test-citizen",
		provType: providers.ProviderTypeCitizen,
		lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			return citizenEvidence(citizenRecord), nil
		},
	}

	orch := newTestOrchestrator(citizenProv, nil)
	svc := New(orch, cache, nil, true) // regulated = true but should not minimize

	result, err := svc.CitizenWithDetails(ctx, userID, nationalID)
	s.Require().NoError(err)
	s.Equal(nationalIDStr, result.NationalID)
	s.Equal("Test User", result.FullName)
	s.Equal("1990-01-01", result.DateOfBirth)
	s.Equal("123 Test St", result.Address)
	s.True(result.Valid)
	s.Equal(now, result.CheckedAt)

	// Internal lookups should not write to cache.
	s.Len(cache.saveCitizenCalls, 0)
}

func (s *ServiceSuite) TestCacheSaveErrorsDoNotFail() {
	ctx := context.Background()
	nationalIDStr := "ABC123456"
	nationalID := testNationalID(nationalIDStr)
	userID := testUserID()
	now := time.Now()

	citizenRecord := &models.CitizenRecord{
		NationalID:  nationalIDStr,
		FullName:    "Test User",
		DateOfBirth: "1990-01-01",
		Address:     "123 Test St",
		Valid:       true,
		CheckedAt:   now,
	}
	sanctionsRecord := &models.SanctionsRecord{
		NationalID: nationalIDStr,
		Listed:     false,
		Source:     "test-source",
		CheckedAt:  now,
	}

	s.Run("check ignores cache save errors", func() {
		cache := newStubCache()
		cache.saveCitizenErr = errors.New("cache write failed")
		cache.saveSanctionErr = errors.New("cache write failed")
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Check(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.NotNil(result)
	})

	s.Run("citizen ignores cache save errors", func() {
		cache := newStubCache()
		cache.saveCitizenErr = errors.New("cache write failed")
		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, nil)
		svc := New(orch, cache, nil, false)

		result, err := svc.Citizen(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.NotNil(result)
	})

	s.Run("sanctions ignores cache save errors", func() {
		cache := newStubCache()
		cache.saveSanctionErr = errors.New("cache write failed")
		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(nil, sanctionsProv)
		svc := New(orch, cache, nil, false)

		result, err := svc.Sanctions(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.NotNil(result)
	})
}

func (s *ServiceSuite) TestConsentRequired() {
	ctx := context.Background()
	nationalID := testNationalID("ABC123456")
	userID := testUserID()

	s.Run("returns error when consent is not granted", func() {
		cache := newStubCache()
		consentPort := &stubConsentPort{
			err: &consentError{message: "consent required for purpose: registry_check"},
		}

		orch := newTestOrchestrator(nil, nil)
		svc := New(orch, cache, consentPort, false)

		result, err := svc.Citizen(ctx, userID, nationalID)
		s.Require().Error(err)
		s.Nil(result)
		s.Contains(err.Error(), "consent")
	})

	s.Run("proceeds when consent is granted", func() {
		cache := newStubCache()
		consentPort := &stubConsentPort{err: nil} // consent granted

		citizenRecord := &models.CitizenRecord{
			NationalID: "ABC123456",
			Valid:      true,
			CheckedAt:  time.Now(),
		}

		citizenProv := &stubProvider{
			id:       "test-citizen",
			provType: providers.ProviderTypeCitizen,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return citizenEvidence(citizenRecord), nil
			},
		}

		orch := newTestOrchestrator(citizenProv, nil)
		svc := New(orch, cache, consentPort, false)

		result, err := svc.Citizen(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.NotNil(result)
	})
}

// consentError implements error for testing
type consentError struct {
	message string
}

func (e *consentError) Error() string {
	return e.message
}

// failingAuditStore is a test double that always returns an error.
// Used to test fail-closed audit semantics.
type failingAuditStore struct {
	err error
}

func (f *failingAuditStore) Append(_ context.Context, _ audit.Event) error {
	return f.err
}

func (f *failingAuditStore) ListByUser(_ context.Context, _ id.UserID) ([]audit.Event, error) {
	return nil, f.err
}

func (f *failingAuditStore) ListAll(_ context.Context) ([]audit.Event, error) {
	return nil, f.err
}

func (f *failingAuditStore) ListRecent(_ context.Context, _ int) ([]audit.Event, error) {
	return nil, f.err
}

// newFailingAuditor creates a compliance publisher that will fail on emit.
func newFailingAuditor(err error) *compliance.Publisher {
	return compliance.New(&failingAuditStore{err: err})
}

// newSuccessAuditor creates a compliance publisher with an in-memory store.
func newSuccessAuditor() (*compliance.Publisher, *auditmemory.InMemoryStore) {
	store := auditmemory.NewInMemoryStore()
	return compliance.New(store), store
}

func (s *ServiceSuite) TestSanctionsAuditFailClosed() {
	ctx := context.Background()
	nationalID := testNationalID("ABC123456")
	userID := testUserID()
	now := time.Now()

	s.Run("returns error when cached listed sanctions audit fails", func() {
		cache := newStubCache()
		auditor := newFailingAuditor(errors.New("audit system unavailable"))

		sanctionsRecord := &models.SanctionsRecord{
			NationalID: "ABC123456",
			Listed:     true,
			Source:     "OFAC SDN List",
			CheckedAt:  now,
		}

		_ = cache.SaveSanction(ctx, nationalID, sanctionsRecord)

		orch := newTestOrchestrator(nil, nil)
		svc := New(orch, cache, nil, false, WithAuditor(auditor))

		result, err := svc.Sanctions(ctx, userID, nationalID)
		s.Require().Error(err)
		s.Nil(result)
		s.Contains(err.Error(), "unable to complete sanctions check")
	})

	s.Run("returns error when audit fails for listed sanctions", func() {
		cache := newStubCache()
		auditor := newFailingAuditor(errors.New("audit system unavailable"))

		sanctionsRecord := &models.SanctionsRecord{
			NationalID: "ABC123456",
			Listed:     true, // Listed = critical audit required
			Source:     "OFAC SDN List",
			CheckedAt:  now,
		}

		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(nil, sanctionsProv)
		svc := New(orch, cache, nil, false, WithAuditor(auditor))

		result, err := svc.Sanctions(ctx, userID, nationalID)
		s.Require().Error(err)
		s.Nil(result)
		s.Contains(err.Error(), "unable to complete sanctions check")
	})

	s.Run("returns result when audit succeeds for listed sanctions", func() {
		cache := newStubCache()
		auditor, auditStore := newSuccessAuditor()

		sanctionsRecord := &models.SanctionsRecord{
			NationalID: "ABC123456",
			Listed:     true,
			Source:     "OFAC SDN List",
			CheckedAt:  now,
		}

		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(nil, sanctionsProv)
		svc := New(orch, cache, nil, false, WithAuditor(auditor))

		result, err := svc.Sanctions(ctx, userID, nationalID)
		s.Require().NoError(err)
		s.NotNil(result)
		s.True(result.Listed)

		// Verify audit event was emitted
		events, _ := auditStore.ListAll(ctx)
		s.Len(events, 1)
		s.Equal("registry_sanctions_checked", events[0].Action)
	})

	s.Run("fails when audit fails for non-listed sanctions (fail-closed)", func() {
		cache := newStubCache()
		auditor := newFailingAuditor(errors.New("audit system unavailable"))

		sanctionsRecord := &models.SanctionsRecord{
			NationalID: "ABC123456",
			Listed:     false, // Not listed, but audit is still fail-closed
			Source:     "Test DB",
			CheckedAt:  now,
		}

		sanctionsProv := &stubProvider{
			id:       "test-sanctions",
			provType: providers.ProviderTypeSanctions,
			lookupFn: func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				return sanctionsEvidence(sanctionsRecord), nil
			},
		}

		orch := newTestOrchestrator(nil, sanctionsProv)
		svc := New(orch, cache, nil, false, WithAuditor(auditor))

		result, err := svc.Sanctions(ctx, userID, nationalID)
		// All sanctions audits are now fail-closed for complete audit trail
		s.Require().Error(err)
		s.Nil(result)
		s.Contains(err.Error(), "unable to complete sanctions check")
	})
}

// auditError implements error for testing
type auditError struct { //nolint:unused // test scaffolding for future use
	message string
}

func (e *auditError) Error() string { //nolint:unused // test scaffolding for future use
	return e.message
}
