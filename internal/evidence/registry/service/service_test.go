package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"credo/internal/evidence/registry/models"
	"credo/internal/evidence/registry/providers"
	"credo/internal/evidence/registry/service/mocks"
	"credo/internal/evidence/registry/store"
)

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks CitizenClient,SanctionsClient,CacheStore
type ServiceSuite struct {
	suite.Suite
	ctrl                *gomock.Controller
	mockCitizenClient   *mocks.MockCitizenClient
	mockSanctionsClient *mocks.MockSanctionsClient
	mockCache           *mocks.MockCacheStore
	service             *Service
}

func (s *ServiceSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockCitizenClient = mocks.NewMockCitizenClient(s.ctrl)
	s.mockSanctionsClient = mocks.NewMockSanctionsClient(s.ctrl)
	s.mockCache = mocks.NewMockCacheStore(s.ctrl)

	// Service in non-regulated mode by default
	s.service = &Service{
		citizens:  s.mockCitizenClient,
		sanctions: s.mockSanctionsClient,
		cache:     s.mockCache,
		regulated: false,
	}
}

func (s *ServiceSuite) TearDownTest() {
	s.ctrl.Finish()
}

func TestServiceSuite(t *testing.T) {
	suite.Run(t, new(ServiceSuite))
}

func (s *ServiceSuite) TestCitizen() {
	s.T().Run("returns cached citizen record on cache hit", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindCitizen to return a valid record
		// - Verify no call to citizenClient.Lookup
		// - Assert returned record matches cached record
		t.Skip("Not implemented")
	})

	s.T().Run("fetches from client on cache miss", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindCitizen to return store.ErrNotFound
		// - Mock citizenClient.Lookup to return a valid record
		// - Mock cache.SaveCitizen to succeed
		// - Assert returned record matches client record
		t.Skip("Not implemented")
	})

	s.T().Run("minimizes citizen record in regulated mode", func(t *testing.T) {
		// TODO: Implement test
		// - Create service with regulated: true
		// - Mock cache miss
		// - Mock citizenClient.Lookup to return full record with PII
		// - Mock cache.SaveCitizen
		// - Assert returned record has PII fields cleared
		// - Assert only NationalID and Valid are set
		t.Skip("Not implemented")
	})

	s.T().Run("returns full citizen record in non-regulated mode", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock citizenClient.Lookup to return full record
		// - Mock cache.SaveCitizen
		// - Assert returned record contains all PII fields
		t.Skip("Not implemented")
	})

	s.T().Run("saves fetched record to cache", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock citizenClient.Lookup
		// - Expect cache.SaveCitizen to be called with the record
		t.Skip("Not implemented")
	})

	s.T().Run("handles client lookup error", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock citizenClient.Lookup to return error
		// - Assert error is returned
		// - Verify cache.SaveCitizen is not called
		t.Skip("Not implemented")
	})

	s.T().Run("handles cache find error that is not ErrNotFound", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindCitizen to return non-ErrNotFound error
		// - Assert error is propagated
		// - Verify citizenClient.Lookup is not called
		t.Skip("Not implemented")
	})

	s.T().Run("continues on cache save failure", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock citizenClient.Lookup to succeed
		// - Mock cache.SaveCitizen to return error
		// - Assert no error returned (save failure is ignored)
		// - Assert record from client is still returned
		t.Skip("Not implemented")
	})
}

func (s *ServiceSuite) TestSanctions() {
	s.T().Run("returns cached sanctions record on cache hit", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindSanction to return a valid record
		// - Verify no call to sanctionsClient.Check
		// - Assert returned record matches cached record
		t.Skip("Not implemented")
	})

	s.T().Run("fetches from client on cache miss", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindSanction to return store.ErrNotFound
		// - Mock sanctionsClient.Check to return a valid record
		// - Mock cache.SaveSanction to succeed
		// - Assert returned record matches client record
		t.Skip("Not implemented")
	})

	s.T().Run("saves fetched record to cache", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock sanctionsClient.Check
		// - Expect cache.SaveSanction to be called with the record
		t.Skip("Not implemented")
	})

	s.T().Run("handles client check error", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock sanctionsClient.Check to return error
		// - Assert error is returned
		// - Verify cache.SaveSanction is not called
		t.Skip("Not implemented")
	})

	s.T().Run("handles cache find error that is not ErrNotFound", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindSanction to return non-ErrNotFound error
		// - Assert error is propagated
		// - Verify sanctionsClient.Check is not called
		t.Skip("Not implemented")
	})

	s.T().Run("continues on cache save failure", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache miss
		// - Mock sanctionsClient.Check to succeed
		// - Mock cache.SaveSanction to return error
		// - Assert no error returned (save failure is ignored)
		// - Assert record from client is still returned
		t.Skip("Not implemented")
	})
}

func (s *ServiceSuite) TestCheck() {
	s.T().Run("returns both citizen and sanctions records", func(t *testing.T) {
		// TODO: Implement test
		// - Mock successful Citizen() call
		// - Mock successful Sanctions() call
		// - Assert both records are returned in RegistryResult
		t.Skip("Not implemented")
	})

	s.T().Run("returns error if citizen lookup fails", func(t *testing.T) {
		// TODO: Implement test
		// - Mock cache.FindCitizen to return error
		// - Assert error is propagated
		// - Verify Sanctions() is not called
		t.Skip("Not implemented")
	})

	s.T().Run("returns error if sanctions lookup fails", func(t *testing.T) {
		// TODO: Implement test
		// - Mock successful Citizen() call
		// - Mock cache.FindSanction to return error
		// - Assert error is propagated
		t.Skip("Not implemented")
	})

	s.T().Run("performs lookups sequentially", func(t *testing.T) {
		// TODO: Implement test (if parallel behavior is desired, update this)
		// - Verify Citizen() is called before Sanctions()
		// Note: Current implementation is sequential, not parallel
		t.Skip("Not implemented")
	})
}

func (s *ServiceSuite) TestCheckTransactionSemantics() {
	ctx := context.Background()
	nationalID := "ABC123456"
	now := time.Now()

	citizenRecord := &models.CitizenRecord{
		NationalID:  nationalID,
		FullName:    "Test User",
		DateOfBirth: "1990-01-01",
		Address:     "123 Test St",
		Valid:       true,
		CheckedAt:   now,
	}

	sanctionsRecord := &models.SanctionsRecord{
		NationalID: nationalID,
		Listed:     false,
		Source:     "test-source",
		CheckedAt:  now,
	}

	s.T().Run("caches both records only when both lookups succeed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		// Both cache misses
		mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(nil, store.ErrNotFound)
		mockCache.EXPECT().FindSanction(ctx, nationalID).Return(nil, store.ErrNotFound)

		// Both provider lookups succeed
		mockCitizens.EXPECT().Lookup(ctx, nationalID).Return(citizenRecord, nil)
		mockSanctions.EXPECT().Check(ctx, nationalID).Return(sanctionsRecord, nil)

		// Both should be cached (atomic commit)
		mockCache.EXPECT().SaveCitizen(ctx, citizenRecord).Return(nil)
		mockCache.EXPECT().SaveSanction(ctx, sanctionsRecord).Return(nil)

		result, err := svc.Check(ctx, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord, result.Sanction)
	})

	s.T().Run("does not cache citizen when sanctions lookup fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		// Both cache misses
		mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(nil, store.ErrNotFound)
		mockCache.EXPECT().FindSanction(ctx, nationalID).Return(nil, store.ErrNotFound)

		// Citizen lookup succeeds
		mockCitizens.EXPECT().Lookup(ctx, nationalID).Return(citizenRecord, nil)

		// Sanctions lookup fails
		sanctionsErr := &providers.ProviderError{
			Category:   providers.ErrorTimeout,
			ProviderID: "test-sanctions",
			Message:    "timeout",
		}
		mockSanctions.EXPECT().Check(ctx, nationalID).Return(nil, sanctionsErr)

		// CRITICAL: Neither SaveCitizen nor SaveSanction should be called (atomic rollback)
		// No EXPECT for SaveCitizen or SaveSanction - if called, test will fail

		result, err := svc.Check(ctx, nationalID)
		s.Require().Error(err)
		s.Nil(result)
	})

	s.T().Run("does not cache sanctions when citizen lookup fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		// Both cache misses
		mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(nil, store.ErrNotFound)
		mockCache.EXPECT().FindSanction(ctx, nationalID).Return(nil, store.ErrNotFound)

		// Citizen lookup fails
		citizenErr := &providers.ProviderError{
			Category:   providers.ErrorNotFound,
			ProviderID: "test-citizens",
			Message:    "not found",
		}
		mockCitizens.EXPECT().Lookup(ctx, nationalID).Return(nil, citizenErr)

		// Sanctions client should NOT be called since citizen failed first
		// No EXPECT for sanctionsClient.Check

		// CRITICAL: Neither SaveCitizen nor SaveSanction should be called
		// No EXPECT for SaveCitizen or SaveSanction

		result, err := svc.Check(ctx, nationalID)
		s.Require().Error(err)
		s.Nil(result)
	})

	s.T().Run("uses cached citizen but fetches sanctions when only citizen is cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		// Citizen cache hit, sanctions cache miss
		mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(citizenRecord, nil)
		mockCache.EXPECT().FindSanction(ctx, nationalID).Return(nil, store.ErrNotFound)

		// Citizen client should NOT be called (cache hit)
		// Sanctions provider lookup
		mockSanctions.EXPECT().Check(ctx, nationalID).Return(sanctionsRecord, nil)

		// Only sanctions should be cached (citizen was already cached)
		mockCache.EXPECT().SaveSanction(ctx, sanctionsRecord).Return(nil)

		result, err := svc.Check(ctx, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord, result.Sanction)
	})

	s.T().Run("uses cached sanctions but fetches citizen when only sanctions is cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		// Citizen cache miss, sanctions cache hit
		mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(nil, store.ErrNotFound)
		mockCache.EXPECT().FindSanction(ctx, nationalID).Return(sanctionsRecord, nil)

		// Citizen provider lookup
		mockCitizens.EXPECT().Lookup(ctx, nationalID).Return(citizenRecord, nil)

		// Sanctions client should NOT be called (cache hit)

		// Only citizen should be cached (sanctions was already cached)
		mockCache.EXPECT().SaveCitizen(ctx, citizenRecord).Return(nil)

		result, err := svc.Check(ctx, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord, result.Sanction)
	})

	s.T().Run("returns both cached records without provider calls when fully cached", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		// Both cache hits
		mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(citizenRecord, nil)
		mockCache.EXPECT().FindSanction(ctx, nationalID).Return(sanctionsRecord, nil)

		// No provider calls expected (both cached)
		// No EXPECT for citizenClient.Lookup or sanctionsClient.Check

		// No cache saves expected (both already cached)
		// No EXPECT for SaveCitizen or SaveSanction

		result, err := svc.Check(ctx, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord, result.Sanction)
	})

	s.T().Run("retry after sanctions failure fetches citizen again", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockCache := mocks.NewMockCacheStore(ctrl)
		mockCitizens := mocks.NewMockCitizenClient(ctrl)
		mockSanctions := mocks.NewMockSanctionsClient(ctrl)

		svc := NewService(mockCitizens, mockSanctions, mockCache, false)

		sanctionsErr := &providers.ProviderError{
			Category:   providers.ErrorTimeout,
			ProviderID: "test-sanctions",
			Message:    "timeout",
		}

		// First call: citizen succeeds, sanctions fails, nothing cached
		gomock.InOrder(
			mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(nil, store.ErrNotFound),
			mockCache.EXPECT().FindSanction(ctx, nationalID).Return(nil, store.ErrNotFound),
			mockCitizens.EXPECT().Lookup(ctx, nationalID).Return(citizenRecord, nil),
			mockSanctions.EXPECT().Check(ctx, nationalID).Return(nil, sanctionsErr),
		)

		result, err := svc.Check(ctx, nationalID)
		s.Require().Error(err)
		s.Nil(result)

		// Second call: citizen fetched again (not cached!), sanctions succeeds, both cached
		gomock.InOrder(
			mockCache.EXPECT().FindCitizen(ctx, nationalID).Return(nil, store.ErrNotFound), // Still not cached
			mockCache.EXPECT().FindSanction(ctx, nationalID).Return(nil, store.ErrNotFound),
			mockCitizens.EXPECT().Lookup(ctx, nationalID).Return(citizenRecord, nil), // Fetched again
			mockSanctions.EXPECT().Check(ctx, nationalID).Return(sanctionsRecord, nil),
			mockCache.EXPECT().SaveCitizen(ctx, citizenRecord).Return(nil),
			mockCache.EXPECT().SaveSanction(ctx, sanctionsRecord).Return(nil),
		)

		result, err = svc.Check(ctx, nationalID)
		s.Require().NoError(err)
		s.Equal(citizenRecord, result.Citizen)
		s.Equal(sanctionsRecord, result.Sanction)
	})
}
