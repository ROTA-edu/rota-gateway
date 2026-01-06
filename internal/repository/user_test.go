package repository

import (
	"context"
	"testing"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB creates a test database connection
func setupTestDB(t *testing.T) *database.Postgres {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := database.PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "rota",
		Password: "rota_dev_password_change_in_prod",
		Database: "rota_main",
		SSLMode:  "disable",
	}

	db, err := database.NewPostgres(cfg)
	require.NoError(t, err, "Failed to connect to test database")

	return db
}

// cleanupTestData removes test data after tests
func cleanupTestData(t *testing.T, db *database.Postgres, email string) {
	ctx := context.Background()
	_, err := db.DB.ExecContext(ctx, "DELETE FROM auth.users WHERE email = $1", email)
	if err != nil {
		t.Logf("Warning: Failed to cleanup test data: %v", err)
	}
}

// TestUserRepository_CreateUser tests creating a new user
func TestUserRepository_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-create@example.com"
	defer cleanupTestData(t, db, testEmail)

	user := &User{
		Email:         testEmail,
		EmailVerified: false,
		Role:          "student",
		FullName:      "Test User",
	}

	// Test: Create user
	err := repo.CreateUser(ctx, user)
	assert.NoError(t, err, "CreateUser should not error")
	assert.NotEmpty(t, user.ID, "User ID should be set after creation")
	assert.NotZero(t, user.CreatedAt, "CreatedAt should be set")
}

// TestUserRepository_CreateUser_DuplicateEmail tests duplicate email constraint
func TestUserRepository_CreateUser_DuplicateEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-duplicate@example.com"
	defer cleanupTestData(t, db, testEmail)

	user1 := &User{
		Email: testEmail,
		Role:  "student",
	}

	// Create first user
	err := repo.CreateUser(ctx, user1)
	require.NoError(t, err)

	// Test: Attempt to create duplicate
	user2 := &User{
		Email: testEmail,
		Role:  "teacher",
	}

	err = repo.CreateUser(ctx, user2)
	assert.Error(t, err, "Creating duplicate email should error")
	assert.Contains(t, err.Error(), "duplicate", "Error should mention duplicate")
}

// TestUserRepository_GetUserByEmail tests retrieving user by email
func TestUserRepository_GetUserByEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-getbyemail@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create a user first
	user := &User{
		Email:         testEmail,
		EmailVerified: true,
		Role:          "teacher",
		FullName:      "Get By Email Test",
	}

	err := repo.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test: Get user by email
	retrieved, err := repo.GetUserByEmail(ctx, testEmail)
	assert.NoError(t, err, "GetUserByEmail should not error")
	assert.NotNil(t, retrieved, "User should be found")
	assert.Equal(t, user.ID, retrieved.ID, "User IDs should match")
	assert.Equal(t, user.Email, retrieved.Email, "Emails should match")
	assert.Equal(t, user.Role, retrieved.Role, "Roles should match")
	assert.True(t, retrieved.EmailVerified, "EmailVerified should be true")
}

// TestUserRepository_GetUserByEmail_NotFound tests non-existent email
func TestUserRepository_GetUserByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Test: Get non-existent user
	user, err := repo.GetUserByEmail(ctx, "nonexistent@example.com")
	assert.Error(t, err, "Should error for non-existent user")
	assert.Nil(t, user, "User should be nil")
	assert.Equal(t, ErrUserNotFound, err, "Should return ErrUserNotFound")
}

// TestUserRepository_GetUserByID tests retrieving user by ID
func TestUserRepository_GetUserByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-getbyid@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create a user first
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := repo.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test: Get user by ID
	retrieved, err := repo.GetUserByID(ctx, user.ID)
	assert.NoError(t, err, "GetUserByID should not error")
	assert.NotNil(t, retrieved, "User should be found")
	assert.Equal(t, user.ID, retrieved.ID, "User IDs should match")
	assert.Equal(t, user.Email, retrieved.Email, "Emails should match")
}

// TestUserRepository_GetUserByID_NotFound tests non-existent ID
func TestUserRepository_GetUserByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Test: Get user with non-existent UUID
	user, err := repo.GetUserByID(ctx, "00000000-0000-0000-0000-000000000000")
	assert.Error(t, err, "Should error for non-existent user")
	assert.Nil(t, user, "User should be nil")
	assert.Equal(t, ErrUserNotFound, err, "Should return ErrUserNotFound")
}

// TestUserRepository_UpdateLastLogin tests updating last login timestamp
func TestUserRepository_UpdateLastLogin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-lastlogin@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create a user
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := repo.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test: Update last login
	err = repo.UpdateLastLogin(ctx, user.ID)
	assert.NoError(t, err, "UpdateLastLogin should not error")

	// Verify the update
	retrieved, err := repo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.LastLoginAt, "LastLoginAt should be set")

	// Should be recent (within last 5 seconds)
	timeSinceLogin := time.Since(*retrieved.LastLoginAt)
	assert.Less(t, timeSinceLogin, 5*time.Second, "LastLoginAt should be recent")
}

// TestUserRepository_CreateOAuthAccount tests creating OAuth account
func TestUserRepository_CreateOAuthAccount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-oauth@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create a user first
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := repo.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test: Create OAuth account
	oauth := &OAuthAccount{
		UserID:      user.ID,
		Provider:    "google",
		ProviderID:  "google-user-123",
		AccessToken: "access-token-encrypted",
	}

	err = repo.CreateOAuthAccount(ctx, oauth)
	assert.NoError(t, err, "CreateOAuthAccount should not error")
	assert.NotEmpty(t, oauth.ID, "OAuth ID should be set after creation")
}

// TestUserRepository_GetOAuthAccount tests retrieving OAuth account
func TestUserRepository_GetOAuthAccount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	testEmail := "test-getoauth@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user and OAuth account
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := repo.CreateUser(ctx, user)
	require.NoError(t, err)

	oauth := &OAuthAccount{
		UserID:     user.ID,
		Provider:   "google",
		ProviderID: "google-user-456",
	}

	err = repo.CreateOAuthAccount(ctx, oauth)
	require.NoError(t, err)

	// Test: Get OAuth account
	retrieved, err := repo.GetOAuthAccount(ctx, "google", "google-user-456")
	assert.NoError(t, err, "GetOAuthAccount should not error")
	assert.NotNil(t, retrieved, "OAuth account should be found")
	assert.Equal(t, oauth.ID, retrieved.ID, "OAuth IDs should match")
	assert.Equal(t, oauth.UserID, retrieved.UserID, "User IDs should match")
	assert.Equal(t, oauth.Provider, retrieved.Provider, "Providers should match")
}

// TestUserRepository_GetOAuthAccount_NotFound tests non-existent OAuth account
func TestUserRepository_GetOAuthAccount_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Test: Get non-existent OAuth account
	oauth, err := repo.GetOAuthAccount(ctx, "google", "nonexistent-provider-id")
	assert.Error(t, err, "Should error for non-existent OAuth account")
	assert.Nil(t, oauth, "OAuth account should be nil")
	assert.Equal(t, ErrOAuthAccountNotFound, err, "Should return ErrOAuthAccountNotFound")
}
