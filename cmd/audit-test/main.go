package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

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
		auditpublisher.WithAsyncBuffer(10), // Small buffer to test backpressure
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
	for i := 0; i < 5; i++ {
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
		time.Sleep(50 * time.Millisecond) // Small delay to let worker process
	}

	// Give worker time to process
	time.Sleep(200 * time.Millisecond)

	// Test 2: Flood the buffer to trigger drops
	fmt.Println("\n2. Flooding buffer with 20 events (buffer size is 10)...")
	dropped := 0
	for i := 0; i < 20; i++ {
		event := audit.Event{
			UserID:    id.UserID(uuid.New()),
			Action:    "flood_action",
			Purpose:   "backpressure_test",
			Decision:  "granted",
			Reason:    fmt.Sprintf("flood event %d", i+1),
			RequestID: uuid.New().String(),
		}
		if err := publisher.Emit(ctx, event); err != nil {
			dropped++
		}
	}
	fmt.Printf("   Emitted 20 events, %d dropped due to full buffer\n", dropped)

	// Give worker time to process remaining
	time.Sleep(500 * time.Millisecond)

	// Test 3: Check store contents
	fmt.Println("\n3. Checking store contents...")
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
