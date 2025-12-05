package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	authService "id-gateway/internal/auth/service"
	authStore "id-gateway/internal/auth/store"
	"id-gateway/internal/platform/config"
	"id-gateway/internal/platform/httpserver"
	"id-gateway/internal/platform/logger"
	"id-gateway/internal/platform/metrics"
	httptransport "id-gateway/internal/transport/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// main wires high-level dependencies, exposes the HTTP router, and keeps the
// server lifecycle small. Business logic lives in internal services packages.
func main() {
	cfg := config.FromEnv()
	log := logger.New()

	log.Info("initializing id-gateway",
		"addr", cfg.Addr,
		"regulated_mode", cfg.RegulatedMode,
	)

	// Initialize Prometheus metrics
	m := metrics.New()

	a := authService.NewService(
		authStore.NewInMemoryUserStore(),
		authStore.NewInMemorySessionStore(),
		24*time.Hour, // TODO Make configurable
		authService.WithMetrics(m),
	)
	r := chi.NewRouter()

	// Add Prometheus metrics endpoint
	r.Handle("/metrics", promhttp.Handler())

	authHandler := httptransport.NewAuthHandler(a, log, cfg.RegulatedMode)
	authHandler.Register(r)

	srv := httpserver.New(cfg.Addr, r)

	log.Info("starting http server", "addr", cfg.Addr)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown on SIGINT
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Info("shutting down server gracefully")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	log.Info("server stopped")
}
