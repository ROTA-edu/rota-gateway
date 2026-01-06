package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check endpoints
	r.Get("/health", healthHandler)
	r.Get("/health/live", livenessHandler)
	r.Get("/health/ready", readinessHandler)

	// API routes (to be implemented)
	r.Route("/auth", func(r chi.Router) {
		// OAuth endpoints will be added here
		r.Get("/google/login", notImplementedHandler)
		r.Get("/google/callback", notImplementedHandler)
		r.Post("/logout", notImplementedHandler)
		r.Get("/me", notImplementedHandler)
		r.Post("/refresh", notImplementedHandler)
	})

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("🚀 ROTA Gateway starting on %s (env=%s)", addr, cfg.Env)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","service":"rota-gateway"}`)
}

func livenessHandler(w http.ResponseWriter, r *http.Request) {
	// Liveness probe: server is running
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"alive":true}`)
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	// Readiness probe: server is ready to accept traffic
	// TODO: Check database and Redis connections
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"ready":true}`)
}

func notImplementedHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, `{"error":"endpoint not yet implemented"}`)
}
