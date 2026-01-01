package decision

import (
	"context"
	"time"

	"credo/internal/decision/ports"
	vcmodels "credo/internal/evidence/vc/models"

	"golang.org/x/sync/errgroup"
)

// evidenceFetchResult holds results from a single evidence fetch.
// Each goroutine writes to its own result, avoiding data races.
type evidenceFetchResult struct {
	citizen           *ports.CitizenRecord
	citizenLatency    time.Duration
	sanctions         *ports.SanctionsRecord
	sanctionsLatency  time.Duration
	credential        *vcmodels.CredentialRecord
	credentialLatency time.Duration
}

// gatherEvidence orchestrates parallel evidence gathering with shared context cancellation.
// Each fetch writes to isolated variables to avoid data races, then results are assembled
// after all goroutines complete. The evalTime parameter ensures consistent timestamps
// across the evaluation for deterministic testing and audit trail consistency.
func (s *Service) gatherEvidence(ctx context.Context, req EvaluateRequest, evalTime time.Time) (*GatheredEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// Isolated result holders - each goroutine writes to its own field
	var result evidenceFetchResult

	// Launch evidence fetches based on purpose
	switch req.Purpose {
	case PurposeAgeVerification:
		s.launchCitizenFetch(ctx, g, &result, req)
		s.launchSanctionsFetch(ctx, g, &result, req)
		s.launchCredentialFetch(ctx, g, &result, req)
	case PurposeSanctionsScreening:
		s.launchSanctionsFetch(ctx, g, &result, req)
	}

	// Wait for all goroutines with early cancellation on first failure
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Assemble evidence from isolated results (safe - all goroutines completed)
	return &GatheredEvidence{
		Citizen:    result.citizen,
		Sanctions:  result.sanctions,
		Credential: result.credential,
		FetchedAt:  evalTime,
		Latencies: EvidenceLatencies{
			Citizen:    result.citizenLatency,
			Sanctions:  result.sanctionsLatency,
			Credential: result.credentialLatency,
		},
	}, nil
}

func (s *Service) launchCitizenFetch(
	ctx context.Context,
	g *errgroup.Group,
	result *evidenceFetchResult,
	req EvaluateRequest,
) {
	g.Go(func() error {
		start := time.Now()
		citizen, err := s.registry.CheckCitizen(ctx, req.UserID, req.NationalID)
		latency := time.Since(start)

		// Store latency immediately for metrics (written to isolated field)
		result.citizenLatency = latency
		if s.metrics != nil {
			s.metrics.ObserveEvidenceLatency("citizen", latency)
		}

		if err != nil {
			return err
		}
		result.citizen = citizen
		return nil
	})
}

func (s *Service) launchSanctionsFetch(
	ctx context.Context,
	g *errgroup.Group,
	result *evidenceFetchResult,
	req EvaluateRequest,
) {
	g.Go(func() error {
		start := time.Now()
		sanctions, err := s.registry.CheckSanctions(ctx, req.UserID, req.NationalID)
		latency := time.Since(start)

		result.sanctionsLatency = latency
		if s.metrics != nil {
			s.metrics.ObserveEvidenceLatency("sanctions", latency)
		}

		if err != nil {
			return err
		}
		result.sanctions = sanctions
		return nil
	})
}

func (s *Service) launchCredentialFetch(
	ctx context.Context,
	g *errgroup.Group,
	result *evidenceFetchResult,
	req EvaluateRequest,
) {
	g.Go(func() error {
		start := time.Now()
		cred, err := s.vc.FindBySubjectAndType(ctx, req.UserID, vcmodels.CredentialTypeAgeOver18)
		latency := time.Since(start)

		result.credentialLatency = latency
		if s.metrics != nil {
			s.metrics.ObserveEvidenceLatency("credential", latency)
		}

		// Not finding a credential is not an error - it's just missing evidence
		if err != nil {
			if s.logger != nil {
				s.logger.DebugContext(ctx, "credential lookup failed",
					"user_id", req.UserID,
					"error", err,
				)
			}
			// Don't return error - credential is optional
			return nil
		}
		result.credential = cred
		return nil
	})
}
