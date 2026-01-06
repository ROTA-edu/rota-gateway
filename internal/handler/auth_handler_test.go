package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/auth"
	"github.com/ROTA-edu/rota-gateway/internal/repository"
	"github.com/ROTA-edu/rota-gateway/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// MockAuthService is a mock implementation of AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) GetOrCreateUserFromGoogle(ctx context.Context, googleUser *service.GoogleUserInfo) (*repository.User, error) {
	args := m.Called(ctx, googleUser)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.User), args.Error(1)
}

func (m *MockAuthService) GenerateTokens(ctx context.Context, user *repository.User) (*service.TokenPair, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.TokenPair), args.Error(1)
}

func (m *MockAuthService) ValidateAccessToken(accessToken string) (*auth.Claims, error) {
	args := m.Called(accessToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.Claims), args.Error(1)
}

func (m *MockAuthService) RefreshTokens(ctx context.Context, refreshToken string) (*service.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.TokenPair), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, sessionID string) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *MockAuthService) LogoutAllDevices(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// MockGoogleOAuth is a mock implementation of GoogleOAuth
type MockGoogleOAuth struct {
	mock.Mock
}

func (m *MockGoogleOAuth) GenerateAuthURL(state string) string {
	args := m.Called(state)
	return args.String(0)
}

func (m *MockGoogleOAuth) ExchangeCode(code string) (*oauth2.Token, error) {
	args := m.Called(code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockGoogleOAuth) GetUserInfo(accessToken string) (*auth.GoogleProfile, error) {
	args := m.Called(accessToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.GoogleProfile), args.Error(1)
}

// TestAuthHandler_GoogleLogin tests the /auth/google/login endpoint
func TestAuthHandler_GoogleLogin(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	// Mock Google OAuth URL generation
	mockGoogleOAuth.On("GenerateAuthURL", mock.AnythingOfType("string")).
		Return("https://accounts.google.com/o/oauth2/auth?state=test-state")

	req := httptest.NewRequest(http.MethodGet, "/auth/google/login", nil)
	rec := httptest.NewRecorder()

	// Test: Should redirect to Google
	handler.GoogleLogin(rec, req)

	assert.Equal(t, http.StatusTemporaryRedirect, rec.Code, "Should return 307 redirect")
	assert.Contains(t, rec.Header().Get("Location"), "accounts.google.com", "Should redirect to Google")

	mockGoogleOAuth.AssertExpectations(t)
}

// TestAuthHandler_GoogleCallback tests the /auth/google/callback endpoint
func TestAuthHandler_GoogleCallback(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	// Mock OAuth code exchange
	token := &oauth2.Token{
		AccessToken: "google-access-token",
	}
	mockGoogleOAuth.On("ExchangeCode", "test-code").
		Return(token, nil)

	// Mock getting user info from Google
	googleProfile := &auth.GoogleProfile{
		Email:         "test@gmail.com",
		EmailVerified: true,
		Name:          "Test User",
		Picture:       "https://example.com/avatar.jpg",
		GoogleID:      "google-123456",
	}

	mockGoogleOAuth.On("GetUserInfo", "google-access-token").
		Return(googleProfile, nil)

	// Convert to GoogleUserInfo for service call
	googleUser := &service.GoogleUserInfo{
		Email:         googleProfile.Email,
		EmailVerified: googleProfile.EmailVerified,
		Name:          googleProfile.Name,
		Picture:       googleProfile.Picture,
		Sub:           googleProfile.GoogleID,
	}

	// Mock user creation/retrieval
	user := &repository.User{
		ID:    "user-callback-123",
		Email: "test@gmail.com",
		Role:  "student",
	}

	mockAuthService.On("GetOrCreateUserFromGoogle", mock.Anything, googleUser).
		Return(user, nil)

	// Mock token generation
	tokens := &service.TokenPair{
		AccessToken:  "jwt-access-token",
		RefreshToken: "refresh-token-123",
		ExpiresIn:    86400,
	}

	mockAuthService.On("GenerateTokens", mock.Anything, user).
		Return(tokens, nil)

	// Create request with code and state
	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=test-code&state=test-state", nil)
	rec := httptest.NewRecorder()

	// Test: Should process callback and return tokens
	handler.GoogleCallback(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "Should return 200 OK")

	// Parse response
	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "jwt-access-token", response["access_token"])
	assert.Equal(t, "refresh-token-123", response["refresh_token"])
	assert.Equal(t, float64(86400), response["expires_in"])

	mockGoogleOAuth.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

// TestAuthHandler_GoogleCallback_MissingCode tests callback without code
func TestAuthHandler_GoogleCallback_MissingCode(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	req := httptest.NewRequest(http.MethodGet, "/auth/google/callback", nil)
	rec := httptest.NewRecorder()

	// Test: Should return error for missing code
	handler.GoogleCallback(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "Should return 400 Bad Request")

	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Contains(t, response["error"], "code", "Error should mention missing code")
}

// TestAuthHandler_RefreshToken tests the /auth/refresh endpoint
func TestAuthHandler_RefreshToken(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	// Mock token refresh
	newTokens := &service.TokenPair{
		AccessToken:  "new-jwt-access-token",
		RefreshToken: "new-refresh-token",
		ExpiresIn:    86400,
	}

	mockAuthService.On("RefreshTokens", mock.Anything, "old-refresh-token").
		Return(newTokens, nil)

	// Create request with refresh token
	reqBody := `{"refresh_token": "old-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Test: Should return new tokens
	handler.RefreshToken(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "Should return 200 OK")

	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "new-jwt-access-token", response["access_token"])
	assert.Equal(t, "new-refresh-token", response["refresh_token"])

	mockAuthService.AssertExpectations(t)
}

// TestAuthHandler_RefreshToken_InvalidToken tests refresh with invalid token
func TestAuthHandler_RefreshToken_InvalidToken(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	// Mock token refresh failure
	mockAuthService.On("RefreshTokens", mock.Anything, "invalid-token").
		Return(nil, repository.ErrSessionNotFound)

	reqBody := `{"refresh_token": "invalid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Test: Should return error
	handler.RefreshToken(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "Should return 401 Unauthorized")

	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Contains(t, response["error"], "invalid", "Error should mention invalid token")
}

// TestAuthHandler_Logout tests the /auth/logout endpoint
func TestAuthHandler_Logout(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	// Mock logout
	mockAuthService.On("Logout", mock.Anything, "session-logout-123").
		Return(nil)

	reqBody := `{"session_id": "session-logout-123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Test: Should logout successfully
	handler.Logout(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "Should return 200 OK")

	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, "logged out successfully", response["message"])

	mockAuthService.AssertExpectations(t)
}

// TestAuthHandler_Logout_MissingSessionID tests logout without session ID
func TestAuthHandler_Logout_MissingSessionID(t *testing.T) {
	mockAuthService := new(MockAuthService)
	mockGoogleOAuth := new(MockGoogleOAuth)

	handler := NewAuthHandler(mockAuthService, mockGoogleOAuth)

	reqBody := `{}`
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	// Test: Should return error
	handler.Logout(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "Should return 400 Bad Request")

	var response map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Contains(t, response["error"], "session_id", "Error should mention missing session_id")
}
