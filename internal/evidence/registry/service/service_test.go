package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/store"
	id "credo/pkg/domain"
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

func (c *stubCache) SaveCitizen(_ context.Context, record *models.CitizenRecord, regulated bool) error {
	c.saveCitizenCalls = append(c.saveCitizenCalls, record)
	if c.saveCitizenErr != nil {
		return c.saveCitizenErr
	}
	c.citizenRecords[record.NationalID] = record
	c.regulatedMode[record.NationalID] = regulated
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

func (c *stubCache) SaveSanction(_ context.Context, record *models.SanctionsRecord) error {
	c.saveSanctionCalls = append(c.saveSanctionCalls, record)
	if c.saveSanctionErr != nil {
		return c.saveSanctionErr
	}
	c.sanctionRecords[record.NationalID] = record
	return nil
}

// stubConsentPort is a test double for consent checks
type stubConsentPort struct {
	err error
}

func (c *stubConsentPort) RequireConsent(_ context.Context, _, _ string) error {
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
		Data: map[string]interface{}{
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
		Data: map[string]interface{}{
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
	return orchestrator.NewOrchestrator(orchestrator.OrchestratorConfig{
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
