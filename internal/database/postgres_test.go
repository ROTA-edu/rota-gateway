package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresConfig_Valid tests creating a Postgres connection with valid config
func TestPostgresConfig_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "rota",
		Password: "rota_dev_password_change_in_prod",
		Database: "rota_main",
		SSLMode:  "disable",
	}

	pg, err := NewPostgres(cfg)
	require.NoError(t, err, "NewPostgres should not error with valid config")
	require.NotNil(t, pg, "Postgres instance should not be nil")
	defer pg.Close()

	// Verify connection works
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = pg.Ping(ctx)
	assert.NoError(t, err, "Ping should succeed")
}

// TestPostgresConfig_InvalidHost tests connection with invalid host
func TestPostgresConfig_InvalidHost(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := PostgresConfig{
		Host:     "invalid-host-that-does-not-exist",
		Port:     5432,
		User:     "rota",
		Password: "rota_dev_password_change_in_prod",
		Database: "rota_main",
		SSLMode:  "disable",
	}

	_, err := NewPostgres(cfg)
	assert.Error(t, err, "NewPostgres should error with invalid host")
}

// TestPostgresHealth tests the Health check
func TestPostgresHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "rota",
		Password: "rota_dev_password_change_in_prod",
		Database: "rota_main",
		SSLMode:  "disable",
	}

	pg, err := NewPostgres(cfg)
	require.NoError(t, err)
	defer pg.Close()

	ctx := context.Background()
	err = pg.Health(ctx)
	assert.NoError(t, err, "Health check should pass")

	// Check stats
	stats := pg.Stats()
	assert.Greater(t, stats.OpenConnections, 0, "Should have at least one open connection")
}

// TestPostgresWithTx tests transaction handling
func TestPostgresWithTx(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "rota",
		Password: "rota_dev_password_change_in_prod",
		Database: "rota_main",
		SSLMode:  "disable",
	}

	pg, err := NewPostgres(cfg)
	require.NoError(t, err)
	defer pg.Close()

	ctx := context.Background()

	// Test successful transaction
	t.Run("successful transaction", func(t *testing.T) {
		err := pg.WithTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "SELECT 1")
			return err
		})
		assert.NoError(t, err, "Transaction should succeed")
	})

	// Test transaction rollback on error
	t.Run("rollback on error", func(t *testing.T) {
		err := pg.WithTx(ctx, func(tx *sql.Tx) error {
			return assert.AnError // Simulate error
		})
		assert.Error(t, err, "Transaction should error and rollback")
	})
}

// TestPostgresConnectionPool tests connection pool settings
func TestPostgresConnectionPool(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := PostgresConfig{
		Host:            "localhost",
		Port:            5432,
		User:            "rota",
		Password:        "rota_dev_password_change_in_prod",
		Database:        "rota_main",
		SSLMode:         "disable",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 10 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}

	pg, err := NewPostgres(cfg)
	require.NoError(t, err)
	defer pg.Close()

	stats := pg.Stats()
	assert.LessOrEqual(t, stats.OpenConnections, cfg.MaxOpenConns, "Open connections should not exceed max")
}

// TestPostgresClose tests closing the connection
func TestPostgresClose(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "rota",
		Password: "rota_dev_password_change_in_prod",
		Database: "rota_main",
		SSLMode:  "disable",
	}

	pg, err := NewPostgres(cfg)
	require.NoError(t, err)

	// Close the connection
	err = pg.Close()
	assert.NoError(t, err, "Close should not error")

	// Ping should fail after close
	ctx := context.Background()
	err = pg.Ping(ctx)
	assert.Error(t, err, "Ping should fail after close")
}
