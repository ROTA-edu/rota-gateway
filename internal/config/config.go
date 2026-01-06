package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all configuration for the gateway
type Config struct {
	// Server
	Port int
	Env  string

	// Auth
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	JWTSecret          string
	JWTIssuer          string
	JWTAudience        string
	JWTExpiryHours     int

	// Database
	DatabaseURL string

	// Redis
	RedisURL string

	// CORS
	AllowedOrigins []string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	port, err := strconv.Atoi(getEnv("PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid PORT: %w", err)
	}

	jwtExpiry, err := strconv.Atoi(getEnv("JWT_EXPIRY_HOURS", "24"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_EXPIRY_HOURS: %w", err)
	}

	cfg := &Config{
		Port: port,
		Env:  getEnv("ENV", "development"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		JWTIssuer:          getEnv("JWT_ISSUER", "rota-gateway"),
		JWTAudience:        getEnv("JWT_AUDIENCE", "rota-platform"),
		JWTExpiryHours:     jwtExpiry,

		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),

		AllowedOrigins: []string{
			getEnv("PLATFORM_URL", "http://localhost:5173"),
			getEnv("ATLAS_URL", "http://localhost:5174"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate checks that all required config values are set
func (c *Config) Validate() error {
	if c.GoogleClientID == "" {
		return fmt.Errorf("GOOGLE_CLIENT_ID is required")
	}
	if c.GoogleClientSecret == "" {
		return fmt.Errorf("GOOGLE_CLIENT_SECRET is required")
	}
	if c.GoogleRedirectURL == "" {
		return fmt.Errorf("GOOGLE_REDIRECT_URL is required")
	}
	if c.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	return nil
}

// IsProd returns true if the environment is production
func (c *Config) IsProd() bool {
	return c.Env == "production"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
