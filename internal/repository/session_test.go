package repository

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupSessionData removes test session data
func cleanupSessionData(t *testing.T, db *database.Postgres, userID string) {
	ctx := context.Background()
	_, err := db.DB.ExecContext(ctx, "DELETE FROM auth.sessions WHERE user_id = $1", userID)
	if err != nil {
		t.Logf("Warning: Failed to cleanup session data: %v", err)
	}
}

// TestSessionRepository_CreateSession tests creating a new session
func TestSessionRepository_CreateSession(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-session@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create a user first
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	// Test: Create session
	session := &Session{
		UserID:       user.ID,
		RefreshToken: "hashed-refresh-token-123",
		DeviceInfo:   `{"device": "chrome", "os": "macos"}`,
		IPAddress:    "192.168.1.1",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	err = sessionRepo.CreateSession(ctx, session)
	assert.NoError(t, err, "CreateSession should not error")
	assert.NotEmpty(t, session.ID, "Session ID should be set")
	assert.NotZero(t, session.CreatedAt, "CreatedAt should be set")
}

// TestSessionRepository_GetSessionByToken tests retrieving session by refresh token
func TestSessionRepository_GetSessionByToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-getsession@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user and session
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	session := &Session{
		UserID:       user.ID,
		RefreshToken: "unique-hashed-token-456",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	err = sessionRepo.CreateSession(ctx, session)
	require.NoError(t, err)

	// Test: Get session by token
	retrieved, err := sessionRepo.GetSessionByToken(ctx, "unique-hashed-token-456")
	assert.NoError(t, err, "GetSessionByToken should not error")
	assert.NotNil(t, retrieved, "Session should be found")
	assert.Equal(t, session.ID, retrieved.ID, "Session IDs should match")
	assert.Equal(t, session.UserID, retrieved.UserID, "User IDs should match")
	assert.Equal(t, session.RefreshToken, retrieved.RefreshToken, "Tokens should match")
}

// TestSessionRepository_GetSessionByToken_NotFound tests non-existent token
func TestSessionRepository_GetSessionByToken_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	// Test: Get non-existent session
	session, err := sessionRepo.GetSessionByToken(ctx, "nonexistent-token")
	assert.Error(t, err, "Should error for non-existent token")
	assert.Nil(t, session, "Session should be nil")
	assert.Equal(t, ErrSessionNotFound, err, "Should return ErrSessionNotFound")
}

// TestSessionRepository_GetSessionByToken_Expired tests expired session
func TestSessionRepository_GetSessionByToken_Expired(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-expired@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	// Create expired session
	session := &Session{
		UserID:       user.ID,
		RefreshToken: "expired-token-789",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // 1 hour ago
	}

	err = sessionRepo.CreateSession(ctx, session)
	require.NoError(t, err)

	// Test: Get expired session should return error
	retrieved, err := sessionRepo.GetSessionByToken(ctx, "expired-token-789")
	assert.Error(t, err, "Should error for expired session")
	assert.Nil(t, retrieved, "Session should be nil")
	assert.Equal(t, ErrSessionExpired, err, "Should return ErrSessionExpired")
}

// TestSessionRepository_DeleteSession tests deleting a session
func TestSessionRepository_DeleteSession(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-deletesession@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user and session
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	session := &Session{
		UserID:       user.ID,
		RefreshToken: "token-to-delete",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	err = sessionRepo.CreateSession(ctx, session)
	require.NoError(t, err)

	// Test: Delete session
	err = sessionRepo.DeleteSession(ctx, session.ID)
	assert.NoError(t, err, "DeleteSession should not error")

	// Verify deletion
	retrieved, err := sessionRepo.GetSessionByToken(ctx, "token-to-delete")
	assert.Error(t, err, "Should error after deletion")
	assert.Nil(t, retrieved, "Session should not be found after deletion")
}

// TestSessionRepository_DeleteUserSessions tests deleting all sessions for a user
func TestSessionRepository_DeleteUserSessions(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-deleteusersessions@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	// Create multiple sessions
	session1 := &Session{
		UserID:       user.ID,
		RefreshToken: "token-1",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	session2 := &Session{
		UserID:       user.ID,
		RefreshToken: "token-2",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	err = sessionRepo.CreateSession(ctx, session1)
	require.NoError(t, err)

	err = sessionRepo.CreateSession(ctx, session2)
	require.NoError(t, err)

	// Test: Delete all user sessions
	err = sessionRepo.DeleteUserSessions(ctx, user.ID)
	assert.NoError(t, err, "DeleteUserSessions should not error")

	// Verify both sessions are deleted
	_, err = sessionRepo.GetSessionByToken(ctx, "token-1")
	assert.Error(t, err, "Session 1 should be deleted")

	_, err = sessionRepo.GetSessionByToken(ctx, "token-2")
	assert.Error(t, err, "Session 2 should be deleted")
}

// TestSessionRepository_CleanupExpiredSessions tests cleanup of expired sessions
func TestSessionRepository_CleanupExpiredSessions(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-cleanup@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	// Create expired session
	expiredSession := &Session{
		UserID:       user.ID,
		RefreshToken: "expired-for-cleanup",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}

	// Create valid session
	validSession := &Session{
		UserID:       user.ID,
		RefreshToken: "valid-for-cleanup",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	err = sessionRepo.CreateSession(ctx, expiredSession)
	require.NoError(t, err)

	err = sessionRepo.CreateSession(ctx, validSession)
	require.NoError(t, err)

	// Test: Cleanup expired sessions
	count, err := sessionRepo.CleanupExpiredSessions(ctx)
	assert.NoError(t, err, "CleanupExpiredSessions should not error")
	assert.GreaterOrEqual(t, count, int64(1), "Should cleanup at least 1 expired session")

	// Verify expired session is deleted
	_, err = sessionRepo.GetSessionByToken(ctx, "expired-for-cleanup")
	assert.Error(t, err, "Expired session should be deleted")

	// Verify valid session still exists
	retrieved, err := sessionRepo.GetSessionByToken(ctx, "valid-for-cleanup")
	assert.NoError(t, err, "Valid session should still exist")
	assert.NotNil(t, retrieved, "Valid session should be found")
}

// TestSessionRepository_UpdateLastUsed tests updating last_used_at timestamp
func TestSessionRepository_UpdateLastUsed(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	sessionRepo := NewSessionRepository(db)
	ctx := context.Background()

	testEmail := "test-lastused@example.com"
	defer cleanupTestData(t, db, testEmail)

	// Create user and session
	user := &User{
		Email: testEmail,
		Role:  "student",
	}

	err := userRepo.CreateUser(ctx, user)
	require.NoError(t, err)
	defer cleanupSessionData(t, db, user.ID)

	session := &Session{
		UserID:       user.ID,
		RefreshToken: "token-lastused",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	err = sessionRepo.CreateSession(ctx, session)
	require.NoError(t, err)

	// Wait a moment to ensure timestamp difference
	time.Sleep(100 * time.Millisecond)

	// Test: Update last used
	err = sessionRepo.UpdateLastUsed(ctx, session.ID)
	assert.NoError(t, err, "UpdateLastUsed should not error")

	// Verify the update
	retrieved, err := sessionRepo.GetSessionByToken(ctx, "token-lastused")
	require.NoError(t, err)
	assert.True(t, retrieved.LastUsedAt.After(session.CreatedAt), "LastUsedAt should be after CreatedAt")
}
