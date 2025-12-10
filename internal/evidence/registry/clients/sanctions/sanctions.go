package sanctions

import (
	"context"
	"credo/internal/evidence/registry/models"
	"time"
)

// Client queries a sanctions list. The gateway keeps the interface
// small so tests can stub quickly.

type Client struct {
	Latency time.Duration
	Listed  bool
}

func (c Client) Check(_ context.Context, nationalID string) (*models.SanctionsRecord, error) {
	time.Sleep(c.Latency)
	return &models.SanctionsRecord{
		NationalID: nationalID,
		Listed:     c.Listed,
		Source:     "mock_sanctions",
	}, nil
}
