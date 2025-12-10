package citizen

import (
	"context"
	"credo/internal/evidence/registry/models"
	"time"
)

// Citint queries a citizen registry. Mock implementations use
// deterministic data and a configurable latency to mimic real-world calls.
type Citint interface {
	Lookup(ctx context.Context, nationalID string) (models.CitizenRecord, error)
}

type MockClient struct {
	Latency       time.Duration
	RegulatedMode bool
}

func (c MockClient) Lookup(_ context.Context, nationalID string) (*models.CitizenRecord, error) {
	time.Sleep(c.Latency)
	record := models.CitizenRecord{
		NationalID:  nationalID,
		FullName:    "Sample Citizen",
		DateOfBirth: "1990-02-03",
		Valid:       true,
	}
	if c.RegulatedMode {
		minimized := models.MinimizeCitizenRecord(record)
		return &minimized, nil
	}
	return &record, nil
}
