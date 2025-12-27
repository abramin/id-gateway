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

func newStubProvider(id string, provType providers.ProviderType) *stubProvider {
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
		Data:         map[string]interface{}{"national_id": filters["national_id"]},
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

func (s *OrchestratorSuite) TestBackoffBehavior() {
	s.Run("retries with exponential backoff on retryable errors", func() {
		attempts := atomic.Int32{}
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		prov.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			count := attempts.Add(1)
			if count < 3 {
				return nil, providers.NewProviderError(
					providers.ErrorTimeout,
					"test-citizen",
					"timeout",
					nil,
				)
			}
			return &providers.Evidence{
				ProviderID:   "test-citizen",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   1.0,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Backoff: BackoffConfig{
				InitialDelay: 10 * time.Millisecond,
				MaxDelay:     100 * time.Millisecond,
				MaxRetries:   3,
				Multiplier:   2.0,
			},
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})

		s.Require().NoError(err)
		s.Require().NotNil(result)
		s.Len(result.Evidence, 1)
		s.Equal(int32(3), attempts.Load(), "should have retried 3 times")
	})

	s.Run("does not retry non-retryable errors", func() {
		attempts := atomic.Int32{}
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		prov.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			attempts.Add(1)
			return nil, providers.NewProviderError(
				providers.ErrorNotFound,
				"test-citizen",
				"citizen not found",
				nil,
			)
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Backoff: BackoffConfig{
				InitialDelay: 10 * time.Millisecond,
				MaxRetries:   3,
			},
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})

		s.Require().Error(err)
		s.Equal(providers.ErrAllProvidersFailed, err)
		s.NotNil(result)
		s.Equal(int32(1), attempts.Load(), "should not retry non-retryable errors")
	})

	s.Run("respects max retries limit", func() {
		attempts := atomic.Int32{}
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		prov.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			attempts.Add(1)
			return nil, providers.NewProviderError(
				providers.ErrorTimeout,
				"test-citizen",
				"timeout",
				nil,
			)
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Backoff: BackoffConfig{
				InitialDelay: 1 * time.Millisecond,
				MaxRetries:   2, // Only 2 retries (3 total attempts)
			},
		})

		ctx := context.Background()
		_, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})

		s.Require().Error(err)
		s.Equal(int32(3), attempts.Load(), "should attempt initial + 2 retries = 3 total")
	})

	s.Run("backoff delays increase exponentially", func() {
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		attempts := atomic.Int32{}
		prov.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			count := attempts.Add(1)
			if count < 4 {
				return nil, providers.NewProviderError(
					providers.ErrorTimeout,
					"test-citizen",
					"timeout",
					nil,
				)
			}
			return &providers.Evidence{
				ProviderID:   "test-citizen",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   1.0,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Backoff: BackoffConfig{
				InitialDelay: 20 * time.Millisecond,
				MaxDelay:     500 * time.Millisecond,
				MaxRetries:   4,
				Multiplier:   2.0,
			},
		})

		start := time.Now()
		ctx := context.Background()
		_, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})
		elapsed := time.Since(start)

		s.Require().NoError(err)
		// Expected delays: 20ms + 40ms + 80ms = 140ms minimum
		s.GreaterOrEqual(elapsed, 100*time.Millisecond, "backoff delays should accumulate")
	})
}

func (s *OrchestratorSuite) TestContextCancellation() {
	s.Run("cancels lookup when context is cancelled", func() {
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		lookupStarted := make(chan struct{})
		prov.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			close(lookupStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyPrimary,
			DefaultTimeout:  5 * time.Second,
		})

		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		var lookupErr error
		var result *LookupResult
		go func() {
			result, lookupErr = orch.Lookup(ctx, LookupRequest{
				Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
				Filters: map[string]string{"national_id": "ABC123"},
			})
			close(done)
		}()

		<-lookupStarted
		cancel()
		<-done

		s.Require().Error(lookupErr)
		// The orchestrator wraps provider errors in ErrAllProvidersFailed
		s.Equal(providers.ErrAllProvidersFailed, lookupErr)
		// The underlying context.Canceled error should be recorded in the provider errors
		s.Require().NotNil(result)
		s.ErrorIs(result.Errors["test-citizen"], context.Canceled)
	})

	s.Run("cancels backoff wait when context is cancelled", func() {
		attempts := atomic.Int32{}
		prov := newStubProvider("test-citizen", providers.ProviderTypeCitizen)
		prov.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			attempts.Add(1)
			return nil, providers.NewProviderError(
				providers.ErrorTimeout,
				"test-citizen",
				"timeout",
				nil,
			)
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov)

		orch := New(OrchestratorConfig{
			Registry:        registry,
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
		_, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})
		elapsed := time.Since(start)

		s.Require().Error(err)
		s.Less(elapsed, 500*time.Millisecond, "should cancel before full backoff delay")
		s.Equal(int32(1), attempts.Load(), "should stop after first attempt when context cancelled during backoff")
	})
}

func (s *OrchestratorSuite) TestParallelStrategy() {
	s.Run("queries all providers in parallel", func() {
		prov1Started := make(chan struct{})
		prov2Started := make(chan struct{})
		prov1Done := make(chan struct{})
		prov2Done := make(chan struct{})

		prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
		prov1.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			close(prov1Started)
			<-prov1Done
			return &providers.Evidence{
				ProviderID:   "citizen-1",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.9,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
		prov2.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			close(prov2Started)
			<-prov2Done
			return &providers.Evidence{
				ProviderID:   "citizen-2",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.8,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov1)
		_ = registry.Register(prov2)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyParallel,
			DefaultTimeout:  5 * time.Second,
		})

		done := make(chan struct{})
		go func() {
			ctx := context.Background()
			_, _ = orch.Lookup(ctx, LookupRequest{
				Types:    []providers.ProviderType{providers.ProviderTypeCitizen},
				Strategy: StrategyParallel,
				Filters:  map[string]string{"national_id": "ABC123"},
			})
			close(done)
		}()

		// Both providers should start before either completes (parallel execution)
		<-prov1Started
		<-prov2Started

		// Complete both
		close(prov1Done)
		close(prov2Done)
		<-done
	})

	s.Run("returns partial results when some providers fail", func() {
		prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
		prov1.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return &providers.Evidence{
				ProviderID:   "citizen-1",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.9,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
		prov2.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return nil, providers.NewProviderError(
				providers.ErrorProviderOutage,
				"citizen-2",
				"service unavailable",
				nil,
			)
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov1)
		_ = registry.Register(prov2)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyParallel,
			DefaultTimeout:  5 * time.Second,
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:    []providers.ProviderType{providers.ProviderTypeCitizen},
			Strategy: StrategyParallel,
			Filters:  map[string]string{"national_id": "ABC123"},
		})

		s.Require().NoError(err)
		s.Len(result.Evidence, 1, "should return evidence from successful provider")
		s.Equal("citizen-1", result.Evidence[0].ProviderID)
		s.Len(result.Errors, 1, "should record error from failed provider")
		s.Contains(result.Errors, "citizen-2")
	})

	s.Run("returns error when all providers fail", func() {
		prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
		prov1.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return nil, providers.NewProviderError(
				providers.ErrorTimeout,
				"citizen-1",
				"timeout",
				nil,
			)
		}

		prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
		prov2.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return nil, providers.NewProviderError(
				providers.ErrorProviderOutage,
				"citizen-2",
				"service unavailable",
				nil,
			)
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov1)
		_ = registry.Register(prov2)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyParallel,
			DefaultTimeout:  5 * time.Second,
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:    []providers.ProviderType{providers.ProviderTypeCitizen},
			Strategy: StrategyParallel,
			Filters:  map[string]string{"national_id": "ABC123"},
		})

		s.Require().Error(err)
		s.Equal(providers.ErrAllProvidersFailed, err)
		s.Len(result.Errors, 2, "should record all errors")
	})
}

func (s *OrchestratorSuite) TestVotingStrategy() {
	s.Run("selects highest confidence evidence", func() {
		prov1 := newStubProvider("citizen-1", providers.ProviderTypeCitizen)
		prov1.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return &providers.Evidence{
				ProviderID:   "citizen-1",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.7,
				Data:         map[string]interface{}{"valid": true, "source": "gov"},
				CheckedAt:    time.Now(),
			}, nil
		}

		prov2 := newStubProvider("citizen-2", providers.ProviderTypeCitizen)
		prov2.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return &providers.Evidence{
				ProviderID:   "citizen-2",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.95,
				Data:         map[string]interface{}{"valid": true, "source": "verified"},
				CheckedAt:    time.Now(),
			}, nil
		}

		prov3 := newStubProvider("citizen-3", providers.ProviderTypeCitizen)
		prov3.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return &providers.Evidence{
				ProviderID:   "citizen-3",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.8,
				Data:         map[string]interface{}{"valid": true, "source": "bank"},
				CheckedAt:    time.Now(),
			}, nil
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(prov1)
		_ = registry.Register(prov2)
		_ = registry.Register(prov3)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyVoting,
			DefaultTimeout:  5 * time.Second,
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:    []providers.ProviderType{providers.ProviderTypeCitizen},
			Strategy: StrategyVoting,
			Filters:  map[string]string{"national_id": "ABC123"},
		})

		s.Require().NoError(err)
		s.Len(result.Evidence, 1, "voting should select one result per type")
		s.Equal("citizen-2", result.Evidence[0].ProviderID, "should select highest confidence")
		s.Equal(0.95, result.Evidence[0].Confidence)
	})
}

func (s *OrchestratorSuite) TestFallbackStrategy() {
	s.Run("uses fallback when primary fails", func() {
		primaryCalled := atomic.Bool{}
		secondaryCalled := atomic.Bool{}

		primaryProv := newStubProvider("citizen-primary", providers.ProviderTypeCitizen)
		primaryProv.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			primaryCalled.Store(true)
			return nil, providers.NewProviderError(
				providers.ErrorProviderOutage,
				"citizen-primary",
				"service unavailable",
				nil,
			)
		}

		secondaryProv := newStubProvider("citizen-secondary", providers.ProviderTypeCitizen)
		secondaryProv.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			secondaryCalled.Store(true)
			return &providers.Evidence{
				ProviderID:   "citizen-secondary",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.9,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(primaryProv)
		_ = registry.Register(secondaryProv)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Chains: map[providers.ProviderType]ProviderChain{
				providers.ProviderTypeCitizen: {
					Primary:   "citizen-primary",
					Secondary: []string{"citizen-secondary"},
				},
			},
			Backoff: BackoffConfig{
				MaxRetries: 0, // No retries to speed up test
			},
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})

		s.Require().NoError(err)
		s.True(primaryCalled.Load(), "primary should be called first")
		s.True(secondaryCalled.Load(), "secondary should be called after primary fails")
		s.Len(result.Evidence, 1)
		s.Equal("citizen-secondary", result.Evidence[0].ProviderID)
	})

	s.Run("does not call fallback when primary succeeds", func() {
		secondaryCalled := atomic.Bool{}

		primaryProv := newStubProvider("citizen-primary", providers.ProviderTypeCitizen)
		primaryProv.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			return &providers.Evidence{
				ProviderID:   "citizen-primary",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   1.0,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		secondaryProv := newStubProvider("citizen-secondary", providers.ProviderTypeCitizen)
		secondaryProv.lookupFn = func(ctx context.Context, filters map[string]string) (*providers.Evidence, error) {
			secondaryCalled.Store(true)
			return &providers.Evidence{
				ProviderID:   "citizen-secondary",
				ProviderType: providers.ProviderTypeCitizen,
				Confidence:   0.9,
				Data:         map[string]interface{}{"valid": true},
				CheckedAt:    time.Now(),
			}, nil
		}

		registry := providers.NewProviderRegistry()
		_ = registry.Register(primaryProv)
		_ = registry.Register(secondaryProv)

		orch := New(OrchestratorConfig{
			Registry:        registry,
			DefaultStrategy: StrategyFallback,
			DefaultTimeout:  5 * time.Second,
			Chains: map[providers.ProviderType]ProviderChain{
				providers.ProviderTypeCitizen: {
					Primary:   "citizen-primary",
					Secondary: []string{"citizen-secondary"},
				},
			},
		})

		ctx := context.Background()
		result, err := orch.Lookup(ctx, LookupRequest{
			Types:   []providers.ProviderType{providers.ProviderTypeCitizen},
			Filters: map[string]string{"national_id": "ABC123"},
		})

		s.Require().NoError(err)
		s.False(secondaryCalled.Load(), "secondary should not be called when primary succeeds")
		s.Len(result.Evidence, 1)
		s.Equal("citizen-primary", result.Evidence[0].ProviderID)
	})
}
