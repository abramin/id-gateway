package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	id "credo/pkg/domain"
	audit "credo/pkg/platform/audit"
	auditmetrics "credo/pkg/platform/audit/metrics"
	auditpublisher "credo/pkg/platform/audit/publisher"
	auditstore "credo/pkg/platform/audit/store/memory"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Create metrics, store, and publisher
	metrics := auditmetrics.New()
	store := auditstore.NewInMemoryStore()
	publisher := auditpublisher.NewPublisher(
		store,
		auditpublisher.WithMetrics(metrics),
		auditpublisher.WithPublisherLogger(logger),
	)

	// Start metrics server in background
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Metrics available at http://localhost:9090/metrics")
		if err := http.ListenAndServe(":9090", nil); err != nil {
			logger.Error("metrics server failed", "error", err)
		}
	}()

	ctx := context.Background()

	fmt.Println("\n=== Audit Publisher Test ===")

	// Test 1: Emit some events normally
	fmt.Println("1. Emitting 5 events (should all succeed)...")
	for i := range 5 {
		event := audit.Event{
			UserID:    id.UserID(uuid.New()),
			Action:    "test_action",
			Purpose:   "manual_test",
			Decision:  "granted",
			Reason:    fmt.Sprintf("test event %d", i+1),
			RequestID: uuid.New().String(),
		}
		if err := publisher.Emit(ctx, event); err != nil {
			fmt.Printf("   Event %d failed: %v\n", i+1, err)
		} else {
			fmt.Printf("   Event %d emitted\n", i+1)
		}
	}

	// Test 2: Check store contents
	fmt.Println("\n2. Checking store contents...")
	allEvents, _ := store.ListAll(ctx)
	fmt.Printf("   Total events in store: %d\n", len(allEvents))

	// Print metrics summary
	fmt.Println("\n=== Metrics Summary ===")
	fmt.Println("View full metrics at: http://localhost:9090/metrics")
	fmt.Println("Filter with: curl -s http://localhost:9090/metrics | grep credo_audit")
	fmt.Println("\nPress Ctrl+C to exit...")

	// Keep server running
	select {}
}
