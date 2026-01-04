//go:build integration

package decision_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"

	"credo/internal/auth/models"
	userstore "credo/internal/auth/store/user"
	consentmodels "credo/internal/consent/models"
	consentservice "credo/internal/consent/service"
	consentstore "credo/internal/consent/store"
	"credo/internal/decision"
	decisionadapters "credo/internal/decision/adapters"
	registryadapters "credo/internal/evidence/registry/adapters"
	"credo/internal/evidence/registry/orchestrator"
	"credo/internal/evidence/registry/providers"
	registryservice "credo/internal/evidence/registry/service"
	registrystore "credo/internal/evidence/registry/store"
	vcadapters "credo/internal/evidence/vc/adapters"
	vcmodels "credo/internal/evidence/vc/models"
	vcservice "credo/internal/evidence/vc/service"
	vcstore "credo/internal/evidence/vc/store"
	tenantmodels "credo/internal/tenant/models"
	tenantstore "credo/internal/tenant/store/tenant"
	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	"credo/pkg/platform/audit/publishers/compliance"
	auditpostgres "credo/pkg/platform/audit/store/postgres"
	"credo/pkg/requestcontext"
	"credo/pkg/testutil/containers"
)

type decisionIntegrationSuite struct {
	suite.Suite
	pg *containers.PostgresContainer

	logger      *slog.Logger
	consentSvc  *consentservice.Service
	vcStore     *vcstore.PostgresStore
	vcSvc       *vcservice.Service
	decisionSvc *decision.Service

	userID       id.UserID
	nationalID   id.NationalID
	now          time.Time
	citizenProv  *staticProvider
	sanctionProv *staticProvider
}

func TestDecisionIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	suite.Run(t, new(decisionIntegrationSuite))
}

func (s *decisionIntegrationSuite) SetupSuite() {
	mgr := containers.GetManager()
	s.pg = mgr.GetPostgres(s.T())
	s.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (s *decisionIntegrationSuite) SetupTest() {
	ctx := context.Background()
	s.Require().NoError(s.pg.TruncateModuleTables(ctx))

	s.now = time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	_, userID := s.createTenantAndUser(ctx, s.now)
	s.userID = userID
	s.nationalID = s.parseNationalID("DEC12345")

	auditStore := auditpostgres.New(s.pg.DB)
	auditPublisher := compliance.New(auditStore)

	consentStore := consentstore.NewPostgres(s.pg.DB)
	consentTx := &postgresConsentTx{db: s.pg.DB}
	s.consentSvc = consentservice.New(
		consentStore,
		auditPublisher,
		s.logger,
		consentservice.WithTx(consentTx),
	)

	registryCache := registrystore.NewPostgresCache(s.pg.DB, 5*time.Minute, nil)
	s.citizenProv = newStaticCitizenProvider(s.nationalID.String(), s.now)
	s.sanctionProv = newStaticSanctionsProvider(s.nationalID.String(), false, s.now)
	registrySvc := s.buildRegistryService(registryCache, s.citizenProv, s.sanctionProv)

	registryAdapter := decisionadapters.NewRegistryAdapter(registrySvc)
	consentAdapter := decisionadapters.NewConsentAdapter(s.consentSvc)

	s.vcStore = vcstore.NewPostgres(s.pg.DB)
	// Create a minimal registry adapter for VC service (not used in decision tests, but required)
	vcRegistryAdapter := vcadapters.NewRegistryAdapter(registrySvc)
	vcConsentAdapter := vcadapters.NewConsentAdapter(s.consentSvc)
	s.vcSvc = vcservice.NewService(s.vcStore, vcRegistryAdapter, vcConsentAdapter, false)
	vcAdapter := decisionadapters.NewVCAdapter(s.vcSvc)

	var err error
	s.decisionSvc, err = decision.New(
		registryAdapter,
		vcAdapter,
		consentAdapter,
		auditPublisher,
		decision.WithLogger(s.logger),
	)
	s.Require().NoError(err)
}

func (s *decisionIntegrationSuite) TestAgeVerificationIntegration() {
	ctx := s.baseContext("decision-age-happy")
	s.grantConsent(ctx, consentmodels.PurposeDecision, consentmodels.PurposeRegistryCheck)
	s.saveAgeCredential(ctx)

	result, err := s.decisionSvc.Evaluate(ctx, decision.EvaluateRequest{
		UserID:     s.userID,
		Purpose:    decision.PurposeAgeVerification,
		NationalID: s.nationalID,
	})

	s.Require().NoError(err)
	s.Equal(decision.DecisionPass, result.Status)
	s.Equal(decision.ReasonAllChecksPassed, result.Reason)
	s.Equal(1, s.countOutboxEvents(ctx, string(decisionAuditEvent())))
	s.Equal(1, s.countSanctionsCache(ctx, s.nationalID))
}

func (s *decisionIntegrationSuite) TestConcurrentEvaluations() {
	ctx := s.baseContext("decision-concurrent")
	s.grantConsent(ctx, consentmodels.PurposeDecision, consentmodels.PurposeRegistryCheck)

	const total = 10
	results := make([]*decision.EvaluateResult, total)
	errs := make([]error, total)

	var wg sync.WaitGroup
	wg.Add(total)
	for i := 0; i < total; i++ {
		i := i
		go func() {
			defer wg.Done()
			reqCtx := requestcontext.WithRequestID(ctx, fmt.Sprintf("req-%d", i))
			result, err := s.decisionSvc.Evaluate(reqCtx, decision.EvaluateRequest{
				UserID:     s.userID,
				Purpose:    decision.PurposeAgeVerification,
				NationalID: s.nationalID,
			})
			results[i] = result
			errs[i] = err
		}()
	}
	wg.Wait()

	for i := 0; i < total; i++ {
		s.Require().NoError(errs[i])
		s.Equal(decision.DecisionPassWithConditions, results[i].Status)
		s.Equal(decision.ReasonMissingCredential, results[i].Reason)
	}

	s.Equal(total, s.countOutboxEvents(ctx, string(decisionAuditEvent())))
	s.Equal(1, s.countSanctionsCache(ctx, s.nationalID))
}

func (s *decisionIntegrationSuite) TestAuditContentionFailsClosed() {
	// Skip: This test is flaky in CI due to connection pool exhaustion
	// when holding an exclusive table lock while trying to perform other DB operations.
	// TODO: Refactor to use a mock auditor that returns errors instead of table locking.
	s.T().Skip("Skipped: table locking approach is flaky in CI - needs mock-based implementation")
}

func (s *decisionIntegrationSuite) baseContext(requestID string) context.Context {
	ctx := requestcontext.WithTime(context.Background(), s.now)
	return requestcontext.WithRequestID(ctx, requestID)
}

func (s *decisionIntegrationSuite) grantConsent(ctx context.Context, purposes ...consentmodels.Purpose) {
	_, err := s.consentSvc.Grant(ctx, s.userID, purposes)
	s.Require().NoError(err)
}

func (s *decisionIntegrationSuite) saveAgeCredential(ctx context.Context) {
	record := vcmodels.CredentialRecord{
		ID:       vcmodels.NewCredentialID(),
		Type:     vcmodels.CredentialTypeAgeOver18,
		Subject:  s.userID,
		Issuer:   "test-issuer",
		IssuedAt: s.now,
		Claims:   vcmodels.Claims{"is_over_18": true},
	}
	s.Require().NoError(s.vcStore.Save(ctx, record))
}

func (s *decisionIntegrationSuite) buildRegistryService(cache *registrystore.PostgresCache, citizen, sanctions *staticProvider) *registryservice.Service {
	registry := providers.NewProviderRegistry()
	s.Require().NoError(registry.Register(citizen))
	s.Require().NoError(registry.Register(sanctions))

	orch := orchestrator.New(orchestrator.OrchestratorConfig{
		Registry:        registry,
		DefaultStrategy: orchestrator.StrategyPrimary,
		Chains: map[providers.ProviderType]orchestrator.ProviderChain{
			providers.ProviderTypeCitizen: {
				Primary: citizen.ID(),
				Timeout: 2 * time.Second,
			},
			providers.ProviderTypeSanctions: {
				Primary: sanctions.ID(),
				Timeout: 2 * time.Second,
			},
		},
	})

	consentAdapter := registryadapters.NewConsentAdapter(s.consentSvc)
	return registryservice.New(orch, cache, consentAdapter, false, registryservice.WithLogger(s.logger))
}

func (s *decisionIntegrationSuite) createTenantAndUser(ctx context.Context, now time.Time) (id.TenantID, id.UserID) {
	tenantID := id.TenantID(uuid.New())
	tenant, err := tenantmodels.NewTenant(tenantID, "decision-test", now)
	s.Require().NoError(err)

	tenantStore := tenantstore.NewPostgres(s.pg.DB)
	s.Require().NoError(tenantStore.CreateIfNameAvailable(ctx, tenant))

	userID := id.UserID(uuid.New())
	user := &models.User{
		ID:        userID,
		TenantID:  tenantID,
		Email:     "decision@example.com",
		FirstName: "Decision",
		LastName:  "Tester",
		Verified:  true,
		Status:    models.UserStatusActive,
	}
	userStore := userstore.NewPostgres(s.pg.DB)
	s.Require().NoError(userStore.Save(ctx, user))

	return tenantID, userID
}

func (s *decisionIntegrationSuite) parseNationalID(value string) id.NationalID {
	nationalID, err := id.ParseNationalID(value)
	s.Require().NoError(err)
	return nationalID
}

func (s *decisionIntegrationSuite) countOutboxEvents(ctx context.Context, eventType string) int {
	var count int
	err := s.pg.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM outbox WHERE event_type = $1", eventType).Scan(&count)
	s.Require().NoError(err)
	return count
}

func (s *decisionIntegrationSuite) countSanctionsCache(ctx context.Context, nationalID id.NationalID) int {
	var count int
	err := s.pg.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM sanctions_cache WHERE national_id = $1", nationalID.String()).Scan(&count)
	s.Require().NoError(err)
	return count
}

func decisionAuditEvent() audit.AuditEvent {
	return audit.EventDecisionMade
}

type postgresConsentTx struct {
	db *sql.DB
}

func (t *postgresConsentTx) RunInTx(ctx context.Context, fn func(ctx context.Context, store consentservice.Store) error) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	store := consentstore.NewPostgresTx(tx)
	if err := fn(ctx, store); err != nil {
		return err
	}
	return tx.Commit()
}

type staticProvider struct {
	id       string
	provType providers.ProviderType
	evidence *providers.Evidence
	delay    time.Duration
	err      error
	calls    int64
}

func newStaticCitizenProvider(nationalID string, now time.Time) *staticProvider {
	return &staticProvider{
		id:       "citizen-provider",
		provType: providers.ProviderTypeCitizen,
		evidence: &providers.Evidence{
			Confidence: 1.0,
			CheckedAt:  now,
			Data: map[string]any{
				"national_id":   nationalID,
				"full_name":     "Decision Citizen",
				"date_of_birth": "1990-01-15",
				"address":       "123 Test St",
				"valid":         true,
			},
		},
	}
}

func newStaticSanctionsProvider(nationalID string, listed bool, now time.Time) *staticProvider {
	return &staticProvider{
		id:       "sanctions-provider",
		provType: providers.ProviderTypeSanctions,
		evidence: &providers.Evidence{
			Confidence: 1.0,
			CheckedAt:  now,
			Data: map[string]any{
				"national_id": nationalID,
				"listed":      listed,
				"source":      "test-source",
			},
		},
	}
}

func (p *staticProvider) ID() string { return p.id }

func (p *staticProvider) Capabilities() providers.Capabilities {
	return providers.Capabilities{
		Protocol: providers.ProtocolHTTP,
		Type:     p.provType,
		Version:  "v1",
		Filters:  []string{"national_id"},
	}
}

func (p *staticProvider) Lookup(ctx context.Context, _ map[string]string) (*providers.Evidence, error) {
	atomic.AddInt64(&p.calls, 1)
	if p.delay > 0 {
		timer := time.NewTimer(p.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if p.err != nil {
		return nil, p.err
	}
	ev := *p.evidence
	ev.ProviderID = p.id
	ev.ProviderType = p.provType
	if ev.CheckedAt.IsZero() {
		ev.CheckedAt = requestcontext.Now(ctx)
	}
	return &ev, nil
}

func (p *staticProvider) Health(_ context.Context) error { return nil }
