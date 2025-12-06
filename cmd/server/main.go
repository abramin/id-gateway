package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	authService "id-gateway/internal/auth/service"
	authStore "id-gateway/internal/auth/store"
	jwttoken "id-gateway/internal/jwt_token"
	"id-gateway/internal/platform/config"
	"id-gateway/internal/platform/httpserver"
	"id-gateway/internal/platform/logger"
	"id-gateway/internal/platform/metrics"
	"id-gateway/internal/platform/middleware"
	httptransport "id-gateway/internal/transport/http"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg := config.FromEnv()
	log := logger.New()

	log.Info("initializing id-gateway",
		"addr", cfg.Addr,
		"regulated_mode", cfg.RegulatedMode,
	)

	// Initialize Prometheus metrics
	m := metrics.New()
	// Initialize JWT service and adapter for auth middleware
	jwtService := jwttoken.NewJWTService(
		cfg.JWTSigningKey,
		"id-gateway",
		"id-gateway-client",
		cfg.TokenTTL,
	)

	a := authService.NewService(
		authStore.NewInMemoryUserStore(),
		authStore.NewInMemorySessionStore(),
		24*time.Hour, // TODO Make configurable
		authService.WithMetrics(m),
		authService.WithLogger(log),
		authService.WithJWTService(jwtService),
	)

	jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)

	r := chi.NewRouter()

	// Add Prometheus metrics endpoint (no auth required)
	r.Handle("/metrics", promhttp.Handler())

	// Common middleware for all routes
	r.Use(middleware.Recovery(log))
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger(log))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(middleware.ContentTypeJSON)
	r.Use(middleware.LatencyMiddleware(m))

	authHandler := httptransport.NewAuthHandler(a, log, cfg.RegulatedMode, m)

	// Public auth endpoints (no JWT required)
	r.Post("/auth/authorize", authHandler.HandleAuthorize)
	r.Post("/auth/token", authHandler.HandleToken)

	// Protected auth endpoints (JWT required)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth(jwtValidator, log))
		r.Get("/auth/userinfo", authHandler.HandleUserInfo)
	})

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
