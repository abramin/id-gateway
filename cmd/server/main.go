package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"id-gateway/internal/platform/config"
	"id-gateway/internal/platform/httpserver"
	"id-gateway/internal/platform/logger"
	httptransport "id-gateway/internal/transport/http"
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

	// TODO: introduce real services when domain logic is implemented.
	handler := httptransport.NewHandler(cfg.RegulatedMode, log)
	router := httptransport.NewRouter(handler, log)

	srv := httpserver.New(cfg.Addr, router)

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
