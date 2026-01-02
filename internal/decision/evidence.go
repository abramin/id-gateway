package decision

import (
	"context"
	"time"

	registrycontracts "credo/contracts/registry"
	vcmodels "credo/internal/evidence/vc/models"

	"golang.org/x/sync/errgroup"
)

// evidenceFetchResult holds results from a single evidence fetch.
// Each goroutine writes to its own result, avoiding data races.
// Uses contract types for cross-module boundary safety.
type evidenceFetchResult struct {
	citizen           *registrycontracts.CitizenRecord
	citizenLatency    time.Duration
	sanctions         *registrycontracts.SanctionsRecord
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
		s.launchEvidenceFetch(ctx, g, "citizen", func(latency time.Duration) {
			result.citizenLatency = latency
		}, func(ctx context.Context) error {
			citizen, err := s.registry.CheckCitizen(ctx, req.UserID, req.NationalID)
			if err != nil {
				return err
			}
			result.citizen = citizen
			return nil
		})
		s.launchEvidenceFetch(ctx, g, "sanctions", func(latency time.Duration) {
			result.sanctionsLatency = latency
		}, func(ctx context.Context) error {
			sanctions, err := s.registry.CheckSanctions(ctx, req.UserID, req.NationalID)
			if err != nil {
				return err
			}
			result.sanctions = sanctions
			return nil
		})
		// Credential lookup is soft-fail: infrastructure errors degrade to pass_with_conditions.
		// Security note: This design prioritizes availability over completeness for advisory
		// age verification. If credential service is unavailable, the user can still proceed
		// but must obtain credentials later. For fail-closed behavior, see sanctions lookup.
		s.launchEvidenceFetch(ctx, g, "credential", func(latency time.Duration) {
			result.credentialLatency = latency
		}, func(ctx context.Context) error {
			cred, err := s.vc.FindBySubjectAndType(ctx, req.UserID, vcmodels.CredentialTypeAgeOver18)
			if err != nil {
				if s.logger != nil {
					s.logger.WarnContext(ctx, "credential lookup failed - degrading to pass_with_conditions",
						"user_id", req.UserID,
						"error", err,
					)
				}
				return nil
			}
			result.credential = cred
			return nil
		})
	case PurposeSanctionsScreening:
		s.launchEvidenceFetch(ctx, g, "sanctions", func(latency time.Duration) {
			result.sanctionsLatency = latency
		}, func(ctx context.Context) error {
			sanctions, err := s.registry.CheckSanctions(ctx, req.UserID, req.NationalID)
			if err != nil {
				return err
			}
			result.sanctions = sanctions
			return nil
		})
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

func (s *Service) launchEvidenceFetch(
	ctx context.Context,
	g *errgroup.Group,
	kind string,
	setLatency func(time.Duration),
	fetch func(context.Context) error,
) {
	g.Go(func() error {
		start := time.Now()
		err := fetch(ctx)
		latency := time.Since(start)
		setLatency(latency)
		if s.metrics != nil {
			s.metrics.ObserveEvidenceLatency(kind, latency)
		}
		return err
	})
}
