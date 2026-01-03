package decision

import (
	"context"
	"time"

	registrycontracts "credo/contracts/registry"
	vccontracts "credo/contracts/vc"

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
	credential        *vccontracts.CredentialPresence
	credentialLatency time.Duration
}

type evidenceTask struct {
	kind       string
	setLatency func(time.Duration)
	fetch      func(context.Context) error
}

// gatherEvidence orchestrates parallel evidence gathering with shared context cancellation.
// Each fetch writes to isolated variables to avoid data races, then results are assembled
// after all goroutines complete. The evalTime parameter ensures consistent timestamps
// across the evaluation for deterministic testing and audit trail consistency.
//
// Side effects: calls external evidence services, spawns goroutines, and records
// per-source latency metrics. Credential fetch failures are treated as soft-fail
// for age verification.
func (s *Service) gatherEvidence(ctx context.Context, req EvaluateRequest, evalTime time.Time) (*GatheredEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, evidenceTimeout)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// Isolated result holders - each goroutine writes to its own field
	var result evidenceFetchResult

	// Launch evidence fetches based on purpose
	for _, task := range s.buildEvidenceTasks(req, &result) {
		s.launchEvidenceFetch(ctx, g, task.kind, task.setLatency, task.fetch)
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

func (s *Service) buildEvidenceTasks(req EvaluateRequest, result *evidenceFetchResult) []evidenceTask {
	switch req.Purpose {
	case PurposeAgeVerification:
		return []evidenceTask{
			s.citizenTask(req, result),
			s.sanctionsTask(req, result),
			s.credentialTask(req, result),
		}
	case PurposeSanctionsScreening:
		return []evidenceTask{
			s.sanctionsTask(req, result),
		}
	default:
		return nil
	}
}

func (s *Service) citizenTask(req EvaluateRequest, result *evidenceFetchResult) evidenceTask {
	return evidenceTask{
		kind: "citizen",
		setLatency: func(latency time.Duration) {
			result.citizenLatency = latency
		},
		fetch: func(ctx context.Context) error {
			citizen, err := s.registry.CheckCitizen(ctx, req.UserID, req.NationalID)
			if err != nil {
				return err
			}
			result.citizen = citizen
			return nil
		},
	}
}

func (s *Service) sanctionsTask(req EvaluateRequest, result *evidenceFetchResult) evidenceTask {
	return evidenceTask{
		kind: "sanctions",
		setLatency: func(latency time.Duration) {
			result.sanctionsLatency = latency
		},
		fetch: func(ctx context.Context) error {
			sanctions, err := s.registry.CheckSanctions(ctx, req.UserID, req.NationalID)
			if err != nil {
				return err
			}
			result.sanctions = sanctions
			return nil
		},
	}
}

func (s *Service) credentialTask(req EvaluateRequest, result *evidenceFetchResult) evidenceTask {
	return evidenceTask{
		kind: "credential",
		setLatency: func(latency time.Duration) {
			result.credentialLatency = latency
		},
		fetch: func(ctx context.Context) error {
			// Credential lookup is soft-fail: infrastructure errors degrade to pass_with_conditions.
			// Security note: This design prioritizes availability over completeness for advisory
			// age verification. If credential service is unavailable, the user can still proceed
			// but must obtain credentials later. For fail-closed behavior, see sanctions lookup.
			cred, err := s.vc.FindCredentialPresence(ctx, req.UserID, vccontracts.CredentialTypeAgeOver18)
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
		},
	}
}

// launchEvidenceFetch runs a single evidence fetch in a goroutine and records latency.
// Side effects: spawns a goroutine, calls external fetchers, and emits metrics.
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
