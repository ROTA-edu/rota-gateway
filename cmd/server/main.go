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

	"github.com/ROTA-edu/rota-gateway/internal/auth"
	"github.com/ROTA-edu/rota-gateway/internal/config"
	"github.com/ROTA-edu/rota-gateway/internal/database"
	"github.com/ROTA-edu/rota-gateway/internal/handler"
	"github.com/ROTA-edu/rota-gateway/internal/repository"
	"github.com/ROTA-edu/rota-gateway/internal/service"
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

	// Initialize database connections
	log.Println("🔌 Connecting to PostgreSQL...")
	pgConfig := database.PostgresConfig{
		Host:            cfg.PostgresHost,
		Port:            cfg.PostgresPort,
		User:            cfg.PostgresUser,
		Password:        cfg.PostgresPassword,
		Database:        cfg.PostgresDatabase,
		SSLMode:         cfg.PostgresSSLMode,
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}

	pg, err := database.NewPostgres(pgConfig)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer pg.Close()
	log.Println("✅ PostgreSQL connected")

	log.Println("🔌 Connecting to Redis...")
	redisConfig := database.RedisConfig{
		Host: cfg.RedisHost,
		Port: cfg.RedisPort,
		DB:   cfg.RedisDB,
	}

	redis, err := database.NewRedis(redisConfig)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redis.Close()
	log.Println("✅ Redis connected")

	// Initialize repositories
	userRepo := repository.NewUserRepository(pg)
	sessionRepo := repository.NewSessionRepository(pg)
	log.Println("✅ Repositories initialized")

	// Initialize Google OAuth
	googleOAuth := auth.NewGoogleOAuth(
		cfg.GoogleClientID,
		cfg.GoogleClientSecret,
		cfg.GoogleRedirectURL,
	)
	log.Println("✅ Google OAuth initialized")

	// Initialize auth service
	authService := service.NewAuthService(userRepo, sessionRepo, cfg.JWTSecret)
	log.Println("✅ Auth service initialized")

	// Initialize auth handler
	authHandler := handler.NewAuthHandler(authService, googleOAuth)
	log.Println("✅ Auth handler initialized")

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
	r.Get("/health/ready", readinessHandlerFunc(pg, redis))

	// Auth routes
	r.Route("/auth", func(r chi.Router) {
		// Google OAuth flow
		r.Get("/google/login", authHandler.GoogleLogin)
		r.Get("/google/callback", authHandler.GoogleCallback)

		// Token management
		r.Post("/refresh", authHandler.RefreshToken)
		r.Post("/logout", authHandler.Logout)

		// User info (to be implemented)
		r.Get("/me", notImplementedHandler)
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

	// Start periodic session cleanup (every hour)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			ctx := context.Background()
			deleted, err := sessionRepo.CleanupExpiredSessions(ctx)
			if err != nil {
				log.Printf("⚠️  Session cleanup error: %v", err)
			} else if deleted > 0 {
				log.Printf("🧹 Cleaned up %d expired sessions", deleted)
			}
		}
	}()

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		log.Println("🛑 Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Shutdown HTTP server
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("⚠️  Server shutdown error: %v", err)
		}

		// Close database connections
		log.Println("🔌 Closing database connections...")
		pg.Close()
		redis.Close()
		log.Println("✅ Graceful shutdown complete")
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

// readinessHandler will be updated to check database connections
func readinessHandlerFunc(pg *database.Postgres, redis *database.Redis) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		// Check PostgreSQL
		if err := pg.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"ready":false,"error":"postgres unreachable"}`)
			return
		}

		// Check Redis
		if err := redis.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"ready":false,"error":"redis unreachable"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"ready":true,"postgres":"ok","redis":"ok"}`)
	}
}

func notImplementedHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	fmt.Fprintf(w, `{"error":"endpoint not yet implemented"}`)
}
