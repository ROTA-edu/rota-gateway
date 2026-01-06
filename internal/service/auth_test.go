package service

import (
	"context"
	"testing"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/auth"
	"github.com/ROTA-edu/rota-gateway/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *repository.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*repository.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.User), args.Error(1)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, id string) (*repository.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.User), args.Error(1)
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) CreateOAuthAccount(ctx context.Context, oauth *repository.OAuthAccount) error {
	args := m.Called(ctx, oauth)
	return args.Error(0)
}

func (m *MockUserRepository) GetOAuthAccount(ctx context.Context, provider, providerID string) (*repository.OAuthAccount, error) {
	args := m.Called(ctx, provider, providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.OAuthAccount), args.Error(1)
}

// MockSessionRepository is a mock implementation of SessionRepository
type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) CreateSession(ctx context.Context, session *repository.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockSessionRepository) GetSessionByToken(ctx context.Context, token string) (*repository.Session, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.Session), args.Error(1)
}

func (m *MockSessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockSessionRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockSessionRepository) UpdateLastUsed(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockSessionRepository) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// TestAuthService_GetOrCreateUserFromGoogle tests user creation from Google OAuth
func TestAuthService_GetOrCreateUserFromGoogle(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret")
	ctx := context.Background()

	googleUser := &GoogleUserInfo{
		Email:         "newuser@gmail.com",
		EmailVerified: true,
		Name:          "New User",
		Picture:       "https://example.com/avatar.jpg",
		Sub:           "google-123456",
	}

	// Test: User doesn't exist, should create new user
	mockUserRepo.On("GetOAuthAccount", ctx, "google", "google-123456").
		Return(nil, repository.ErrOAuthAccountNotFound)

	mockUserRepo.On("CreateUser", ctx, mock.AnythingOfType("*repository.User")).
		Return(nil).
		Run(func(args mock.Arguments) {
			user := args.Get(1).(*repository.User)
			user.ID = "user-new-123"
			user.CreatedAt = time.Now()
		})

	mockUserRepo.On("CreateOAuthAccount", ctx, mock.AnythingOfType("*repository.OAuthAccount")).
		Return(nil)

	user, err := authService.GetOrCreateUserFromGoogle(ctx, googleUser)
	assert.NoError(t, err, "GetOrCreateUserFromGoogle should not error")
	assert.NotNil(t, user, "User should not be nil")
	assert.Equal(t, "newuser@gmail.com", user.Email)
	assert.Equal(t, "student", user.Role, "New users should default to student role")

	mockUserRepo.AssertExpectations(t)
}

// TestAuthService_GetOrCreateUserFromGoogle_ExistingUser tests existing user flow
func TestAuthService_GetOrCreateUserFromGoogle_ExistingUser(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret")
	ctx := context.Background()

	googleUser := &GoogleUserInfo{
		Email: "existing@gmail.com",
		Sub:   "google-existing",
	}

	existingUser := &repository.User{
		ID:    "user-existing-123",
		Email: "existing@gmail.com",
		Role:  "teacher",
	}

	existingOAuth := &repository.OAuthAccount{
		UserID:     "user-existing-123",
		Provider:   "google",
		ProviderID: "google-existing",
	}

	// Test: User exists
	mockUserRepo.On("GetOAuthAccount", ctx, "google", "google-existing").
		Return(existingOAuth, nil)

	mockUserRepo.On("GetUserByID", ctx, "user-existing-123").
		Return(existingUser, nil)

	user, err := authService.GetOrCreateUserFromGoogle(ctx, googleUser)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "user-existing-123", user.ID)
	assert.Equal(t, "teacher", user.Role, "Should preserve existing role")

	mockUserRepo.AssertExpectations(t)
}

// TestAuthService_GenerateTokens tests JWT and refresh token generation
func TestAuthService_GenerateTokens(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret-min-32-chars!!")
	ctx := context.Background()

	user := &repository.User{
		ID:    "user-123",
		Email: "test@example.com",
		Role:  "student",
	}

	// Mock session creation
	mockSessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*repository.Session")).
		Return(nil).
		Run(func(args mock.Arguments) {
			session := args.Get(1).(*repository.Session)
			session.ID = "session-123"
			session.CreatedAt = time.Now()
		})

	mockUserRepo.On("UpdateLastLogin", ctx, "user-123").Return(nil)

	// Test: Generate tokens
	tokens, err := authService.GenerateTokens(ctx, user)
	assert.NoError(t, err, "GenerateTokens should not error")
	assert.NotNil(t, tokens, "Tokens should not be nil")
	assert.NotEmpty(t, tokens.AccessToken, "Access token should not be empty")
	assert.NotEmpty(t, tokens.RefreshToken, "Refresh token should not be empty")
	assert.Greater(t, tokens.ExpiresIn, int64(0), "ExpiresIn should be positive")

	mockSessionRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

// TestAuthService_ValidateAccessToken tests JWT validation
func TestAuthService_ValidateAccessToken(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret-min-32-chars!!")
	ctx := context.Background()

	user := &repository.User{
		ID:    "user-validate-123",
		Email: "validate@example.com",
		Role:  "student",
	}

	// Generate a valid token first
	mockSessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*repository.Session")).
		Return(nil).
		Run(func(args mock.Arguments) {
			session := args.Get(1).(*repository.Session)
			session.ID = "session-validate-123"
		})

	mockUserRepo.On("UpdateLastLogin", ctx, "user-validate-123").Return(nil)

	tokens, err := authService.GenerateTokens(ctx, user)
	require.NoError(t, err)

	// Test: Validate the token
	claims, err := authService.ValidateAccessToken(tokens.AccessToken)
	assert.NoError(t, err, "ValidateAccessToken should not error")
	assert.NotNil(t, claims, "Claims should not be nil")
	assert.Equal(t, "user-validate-123", claims.UserID)
	assert.Equal(t, "validate@example.com", claims.Email)
	assert.Equal(t, "student", claims.Role)
}

// TestAuthService_ValidateAccessToken_Invalid tests invalid token
func TestAuthService_ValidateAccessToken_Invalid(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret-min-32-chars!!")

	// Test: Invalid token
	claims, err := authService.ValidateAccessToken("invalid.jwt.token")
	assert.Error(t, err, "Should error for invalid token")
	assert.Nil(t, claims, "Claims should be nil")
}

// TestAuthService_RefreshTokens tests token refresh flow
func TestAuthService_RefreshTokens(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret-min-32-chars!!")
	ctx := context.Background()

	user := &repository.User{
		ID:    "user-refresh-123",
		Email: "refresh@example.com",
		Role:  "student",
	}

	// Create initial session
	mockSessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*repository.Session")).
		Return(nil).
		Run(func(args mock.Arguments) {
			session := args.Get(1).(*repository.Session)
			session.ID = "session-refresh-123"
		}).Once()

	mockUserRepo.On("UpdateLastLogin", ctx, "user-refresh-123").Return(nil).Once()

	initialTokens, err := authService.GenerateTokens(ctx, user)
	require.NoError(t, err)

	// Mock session retrieval for refresh
	existingSession := &repository.Session{
		ID:           "session-refresh-123",
		UserID:       "user-refresh-123",
		RefreshToken: initialTokens.RefreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	mockSessionRepo.On("GetSessionByToken", ctx, initialTokens.RefreshToken).
		Return(existingSession, nil)

	mockUserRepo.On("GetUserByID", ctx, "user-refresh-123").
		Return(user, nil)

	mockSessionRepo.On("DeleteSession", ctx, "session-refresh-123").Return(nil)

	mockSessionRepo.On("CreateSession", ctx, mock.AnythingOfType("*repository.Session")).
		Return(nil).
		Run(func(args mock.Arguments) {
			session := args.Get(1).(*repository.Session)
			session.ID = "session-new-123"
		})

	mockUserRepo.On("UpdateLastLogin", ctx, "user-refresh-123").Return(nil)

	// Test: Refresh tokens
	newTokens, err := authService.RefreshTokens(ctx, initialTokens.RefreshToken)
	assert.NoError(t, err, "RefreshTokens should not error")
	assert.NotNil(t, newTokens, "New tokens should not be nil")
	assert.NotEqual(t, initialTokens.AccessToken, newTokens.AccessToken, "Access token should be new")
	assert.NotEqual(t, initialTokens.RefreshToken, newTokens.RefreshToken, "Refresh token should rotate")

	mockSessionRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

// TestAuthService_Logout tests logout flow
func TestAuthService_Logout(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockSessionRepo := new(MockSessionRepository)

	authService := NewAuthService(mockUserRepo, mockSessionRepo, "test-jwt-secret")
	ctx := context.Background()

	// Test: Logout (delete session)
	mockSessionRepo.On("DeleteSession", ctx, "session-logout-123").Return(nil)

	err := authService.Logout(ctx, "session-logout-123")
	assert.NoError(t, err, "Logout should not error")

	mockSessionRepo.AssertExpectations(t)
}
