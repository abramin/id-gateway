package orchestrator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"credo/internal/evidence/registry/providers"
)

// stubProvider is a test double for providers.Provider
type stubProvider struct {
	id          string
	provType    providers.ProviderType
	lookupFn    func(ctx context.Context, filters map[string]string) (*providers.Evidence, error)
	healthFn    func(ctx context.Context) error
	callCount   atomic.Int32
	callTimes   []time.Time
	callTimesMu chan struct{} // mutex for callTimes
}

func newStubProvider(id string, provType providers.ProviderType) *stubProvider { //nolint:unparam // provType allows future test scenarios with heterogeneous providers
	return &stubProvider{
		id:          id,
		provType:    provType,
		callTimesMu: make(chan struct{}, 1),
	}
}

func (p *stubProvider) ID() string { return p.id }

func (p *stubProvider) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Protocol: providers.ProtocolHTTP,
		Type:     p.provType,
		Version:  "v1.0.0",
		Filters:  []string{"national_id"},
	}
}

func (p *stubProvider) Lookup(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
	p.callCount.Add(1)

	// Record call time for backoff verification
	select {
	case p.callTimesMu <- struct{}{}:
		p.callTimes = append(p.callTimes, time.Now())
		<-p.callTimesMu
	default:
	}

	if p.lookupFn != nil {
		return p.lookupFn(ctx, filters)
	}
	return &providers.Evidence{
		ProviderID:   p.id,
		ProviderType: p.provType,
		Confidence:   1.0,
		Data:         map[string]any{"national_id": filters["national_id"]},
		CheckedAt:    time.Now(),
	}, nil
}

func (p *stubProvider) Health(ctx context.Context) error {
	if p.healthFn != nil {
		return p.healthFn(ctx)
	}
	return nil
}

type OrchestratorSuite struct {
	suite.Suite
}

func TestOrchestratorSuite(t *testing.T) {
	suite.Run(t, new(OrchestratorSuite))
}

// --- Test Helpers ---

func (s *OrchestratorSuite) evidence(providerID string, confidence float64) *providers.Evidence {
	return &providers.Evidence{
		ProviderID:   providerID,
		ProviderType: providers.ProviderTypeCitizen,
		Confidence:   confidence,
		Data:         map[string]any{"valid": true},
		CheckedAt:    time.Now(),
	}
}

func (s *OrchestratorSuite) evidenceWithData(providerID string, confidence float64, data map[string]any) *providers.Evidence {
	return &providers.Evidence{
		ProviderID:   providerID,
		ProviderType: providers.ProviderTypeCitizen,
		Confidence:   confidence,
		Data:         data,
		CheckedAt:    time.Now(),
	}
}

func (s *OrchestratorSuite) citizenRequest() LookupRequest {
	return LookupRequest{
		Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
		Filters: map[string]string{"national_id": "ABC123"},
	}
}

func (s *OrchestratorSuite) citizenRequestWithStrategy(strategy LookupStrategy) LookupRequest {
	return LookupRequest{
		Types:    []providers.ProviderType{providers.ProviderTypeCitizen},
		Strategy: strategy,
		Filters:  map[string]string{"national_id": "ABC123"},
	}
}

func (s *OrchestratorSuite) newOrchestrator(provs []*stubProvider, cfg OrchestratorConfig) *Orchestrator {
	registry := providers.NewProviderRegistry()
	for _, p := range provs {
		_ = registry.Register(p)
	}
	cfg.Registry = registry
	return New(cfg)
}

func providerError(errType providers.ErrorCategory, provID string) error {
	return providers.NewProviderError(errType, provID, string(errType), nil)
}

func (s *OrchestratorSuite) TestBackoffBehavior() {
	tests := []struct {
		name         string
		errorType    providers.ErrorCategory
		maxRetries   int
		failUntil    int32 // fail until this attempt number (0 = always fail)
		wantAttempts int32
		wantErr      bool
	}{
		{
			name:         "retries with backoff on retryable errors",
			errorType:    providers.ErrorTimeout,
			maxRetries:   3,
			failUntil:    3,
			wantAttempts: 3,
			wantErr:      false,
		},
		{
			name:         "does not retry non-retryable errors",
			errorType:    providers.ErrorNotFound,
			maxRetries:   3,
			failUntil:    0, // always fail
			wantAttempts: 1,
			wantErr:      true,
		},
		{
			name:         "respects max retries limit",
			errorType:    providers.ErrorTimeout,
			maxRetries:   2,
			failUntil:    0, // always fail
			wantAttempts: 3, // initial + 2 retries
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			attempts := atomic.Int32{}
			prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
			prov.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				count := attempts.Add(1)
				if tc.failUntil == 0 || count < tc.failUntil {
					return nil, providerError(tc.errorType, "test-citizen")
				}
				return s.evidence("test-citizen", 1.0), nil
			}

			orch := s.newOrchestrator([]*stubProvider{prov}, OrchestratorConfig{
				DefaultStrategy: StrategyFallback,
				DefaultTimeout:  5 * time.Second,
				Backoff: BackoffConfig{
					InitialDelay: 1 * time.Millisecond,
					MaxRetries:   tc.maxRetries,
				},
			})

			_, err := orch.Lookup(context.Background(), s.citizenRequest())

			if tc.wantErr {
				s.Require().Error(err)
				s.Equal(providers.ErrAllProvidersFailed, err)
			} else {
				s.Require().NoError(err)
			}
			s.Equal(tc.wantAttempts, attempts.Load())
		})
	}

	s.Run("backoff delays increase exponentially", func() {
		attempts := atomic.Int32{}
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		prov.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			if attempts.Add(1) < 4 {
				return nil, providerError(providers.ErrorTimeout, "test-citizen")
			}
			return s.evidence("test-citizen", 1.0), nil
		}

		orch := s.newOrchestrator([]*stubProvider{prov}, OrchestratorConfig{
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Backoff: BackoffConfig{
				InitialDelay: 20 * time.Millisecond,
				MaxDelay:     500 * time.Millisecond,
				MaxRetries:   4,
				Multiplier:   2.0,
			},
		})

		_, err := orch.Lookup(context.Background(), s.citizenRequest())

		s.Require().NoError(err)
		s.Require().Len(prov.callTimes, 4, "expected initial call plus 3 retries")

		firstDelay := prov.callTimes[1].Sub(prov.callTimes[0])
		secondDelay := prov.callTimes[2].Sub(prov.callTimes[1])
		thirdDelay := prov.callTimes[3].Sub(prov.callTimes[2])

		s.GreaterOrEqual(firstDelay, 15*time.Millisecond, "initial backoff should apply")
		s.GreaterOrEqual(secondDelay, 30*time.Millisecond, "backoff delay should increase")
		s.GreaterOrEqual(thirdDelay, 60*time.Millisecond, "backoff delay should keep increasing")
	})
}

func (s *OrchestratorSuite) TestContextCancellation() {
	s.Run("cancels lookup when context is cancelled", func() {
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		lookupStarted := make(chan struct{})
		prov.lookupFn = func(ctx context.Context, _ map[string]string) (*providers.Evidence, error) {
			close(lookupStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}

		orch := s.newOrchestrator([]*stubProvider{prov}, OrchestratorConfig{
			DefaultStrategy: StrategyPrimary,
			DefaultTimeout:  5 * time.Second,
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var lookupErr error
		var result *LookupResult
		go func() {
			result, lookupErr = orch.Lookup(ctx, s.citizenRequest())
			close(done)
		}()

		<-lookupStarted
		cancel()
		<-done

		s.Require().Error(lookupErr)
		s.Equal(providers.ErrAllProvidersFailed, lookupErr)
		s.Require().NotNil(result)
		s.ErrorIs(result.Errors["test-citizen"], context.Canceled)
	})

	s.Run("cancels backoff wait when context is cancelled", func() {
		attempts := atomic.Int32{}
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		prov.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			attempts.Add(1)
			return nil, providerError(providers.ErrorTimeout, "test-citizen")
		}

		orch := s.newOrchestrator([]*stubProvider{prov}, OrchestratorConfig{
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  10 * time.Second,
			Backoff: BackoffConfig{
				InitialDelay: 1 * time.Second, // Long delay to ensure we cancel during wait
				MaxRetries:   5,
			},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := orch.Lookup(ctx, s.citizenRequest())
		elapsed := time.Since(start)

		s.Require().Error(err)
		s.Less(elapsed, 500*time.Millisecond, "should cancel before full backoff delay")
		s.Equal(int32(1), attempts.Load(), "should stop after first attempt when context cancelled during backoff")
	})
}

func (s *OrchestratorSuite) TestParallelStrategy() {
	s.Run("queries all providers in parallel", func() {
		prov1Started, prov2Started := make(chan struct{}), make(chan struct{})
		prov1Done, prov2Done := make(chan struct{}), make(chan struct{})

		prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
		prov1.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			close(prov1Started)
			<-prov1Done
			return s.evidence("citizen-1", 0.9), nil
		}

		prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
		prov2.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			close(prov2Started)
			<-prov2Done
			return s.evidence("citizen-2", 0.8), nil
		}

		orch := s.newOrchestrator([]*stubProvider{prov1, prov2}, OrchestratorConfig{
			DefaultStrategy: StrategyParallel,
			DefaultTimeout:  5 * time.Second,
		})

		done := make(chan struct{})
		go func() {
			_, _ = orch.Lookup(context.Background(), s.citizenRequestWithStrategy(StrategyParallel))
			close(done)
		}()

		// Both providers should start before either completes (parallel execution)
		<-prov1Started
		<-prov2Started

		close(prov1Done)
		close(prov2Done)
		<-done
	})

	tests := []struct {
		name          string
		prov1Succeeds bool
		prov2Succeeds bool
		wantEvidence  int
		wantErrors    int
		wantErr       bool
	}{
		{"partial results when some fail", true, false, 1, 1, false},
		{"error when all fail", false, false, 0, 2, true},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
			if tc.prov1Succeeds {
				prov1.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					return s.evidence("citizen-1", 0.9), nil
				}
			} else {
				prov1.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					return nil, providerError(providers.ErrorTimeout, "citizen-1")
				}
			}

			prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
			if tc.prov2Succeeds {
				prov2.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					return s.evidence("citizen-2", 0.8), nil
				}
			} else {
				prov2.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					return nil, providerError(providers.ErrorProviderOutage, "citizen-2")
				}
			}

			orch := s.newOrchestrator([]*stubProvider{prov1, prov2}, OrchestratorConfig{
				DefaultStrategy: StrategyParallel,
				DefaultTimeout:  5 * time.Second,
			})

			result, err := orch.Lookup(context.Background(), s.citizenRequestWithStrategy(StrategyParallel))

			if tc.wantErr {
				s.Require().Error(err)
				s.Equal(providers.ErrAllProvidersFailed, err)
			} else {
				s.Require().NoError(err)
			}
			s.Len(result.Evidence, tc.wantEvidence)
			s.Len(result.Errors, tc.wantErrors)
		})
	}
}

func (s *OrchestratorSuite) TestVotingStrategy() {
	s.Run("selects highest confidence evidence", func() {
		prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
		prov1.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			return s.evidenceWithData("citizen-1", 0.7, map[string]any{"valid": true, "source": "gov"}), nil
		}

		prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
		prov2.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			return s.evidenceWithData("citizen-2", 0.95, map[string]any{"valid": true, "source": "verified"}), nil
		}

		prov3 := newStubProvider("citizen-3", providers.ProviderTypeCitizen)
		prov3.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
			return s.evidenceWithData("citizen-3", 0.8, map[string]any{"valid": true, "source": "bank"}), nil
		}

		orch := s.newOrchestrator([]*stubProvider{prov1, prov2, prov3}, OrchestratorConfig{
			DefaultStrategy: StrategyVoting,
			DefaultTimeout:  5 * time.Second,
		})

		result, err := orch.Lookup(context.Background(), s.citizenRequestWithStrategy(StrategyVoting))

		s.Require().NoError(err)
		s.Len(result.Evidence, 1, "voting should select one result per type")
		s.Equal("citizen-2", result.Evidence[0].ProviderID, "should select highest confidence")
		s.Equal(0.95, result.Evidence[0].Confidence)
	})
}

func (s *OrchestratorSuite) TestFallbackStrategy() {
	tests := []struct {
		name                string
		primarySucceeds     bool
		wantSecondaryCalled bool
		wantProviderID      string
	}{
		{"uses fallback when primary fails", false, true, "citizen-secondary"},
		{"does not call fallback when primary succeeds", true, false, "citizen-primary"},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			primaryCalled := atomic.Bool{}
			secondaryCalled := atomic.Bool{}

			primaryProv := newStubProvider("citizen-primary", providers.ProviderTypeCitizen)
			if tc.primarySucceeds {
				primaryProv.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					primaryCalled.Store(true)
					return s.evidence("citizen-primary", 1.0), nil
				}
			} else {
				primaryProv.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
					primaryCalled.Store(true)
					return nil, providerError(providers.ErrorProviderOutage, "citizen-primary")
				}
			}

			secondaryProv := newStubProvider("citizen-secondary", providers.ProviderTypeCitizen)
			secondaryProv.lookupFn = func(_ context.Context, _ map[string]string) (*providers.Evidence, error) {
				secondaryCalled.Store(true)
				return s.evidence("citizen-secondary", 0.9), nil
			}

			orch := s.newOrchestrator([]*stubProvider{primaryProv, secondaryProv}, OrchestratorConfig{
				DefaultStrategy: StrategyFallback,
				DefaultTimeout:  5 * time.Second,
				Chains: map[providers.ProviderType]ProviderChain{
					providers.ProviderTypeCitizen: {
						Primary:   "citizen-primary",
						Secondary: []string{"citizen-secondary"},
					},
				},
				Backoff: BackoffConfig{MaxRetries: 0},
			})

			result, err := orch.Lookup(context.Background(), s.citizenRequest())

			s.Require().NoError(err)
			s.True(primaryCalled.Load(), "primary should always be called first")
			s.Equal(tc.wantSecondaryCalled, secondaryCalled.Load())
			s.Len(result.Evidence, 1)
			s.Equal(tc.wantProviderID, result.Evidence[0].ProviderID)
		})
	}
}
