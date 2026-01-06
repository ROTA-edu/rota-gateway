package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/auth"
	"github.com/ROTA-edu/rota-gateway/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// GoogleUserInfo represents user information from Google OAuth
type GoogleUserInfo struct {
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Sub           string // Google user ID
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // seconds
}

// AuthService handles authentication business logic
type AuthService struct {
	userRepo    UserRepository
	sessionRepo SessionRepository
	jwtSecret   string
}

// UserRepository interface for dependency injection
type UserRepository interface {
	CreateUser(ctx context.Context, user *repository.User) error
	GetUserByEmail(ctx context.Context, email string) (*repository.User, error)
	GetUserByID(ctx context.Context, id string) (*repository.User, error)
	UpdateLastLogin(ctx context.Context, userID string) error
	CreateOAuthAccount(ctx context.Context, oauth *repository.OAuthAccount) error
	GetOAuthAccount(ctx context.Context, provider, providerID string) (*repository.OAuthAccount, error)
}

// SessionRepository interface for dependency injection
type SessionRepository interface {
	CreateSession(ctx context.Context, session *repository.Session) error
	GetSessionByToken(ctx context.Context, token string) (*repository.Session, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	UpdateLastUsed(ctx context.Context, sessionID string) error
	CleanupExpiredSessions(ctx context.Context) (int64, error)
}

// NewAuthService creates a new AuthService
func NewAuthService(userRepo UserRepository, sessionRepo SessionRepository, jwtSecret string) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtSecret:   jwtSecret,
	}
}

// GetOrCreateUserFromGoogle gets an existing user or creates a new one from Google OAuth
func (s *AuthService) GetOrCreateUserFromGoogle(ctx context.Context, googleUser *GoogleUserInfo) (*repository.User, error) {
	// Check if OAuth account exists
	oauthAccount, err := s.userRepo.GetOAuthAccount(ctx, "google", googleUser.Sub)
	if err == nil {
		// Existing user - get user by ID
		user, err := s.userRepo.GetUserByID(ctx, oauthAccount.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user by id: %w", err)
		}
		return user, nil
	}

	// OAuth account not found - check if user exists by email
	if err != repository.ErrOAuthAccountNotFound {
		return nil, fmt.Errorf("failed to get oauth account: %w", err)
	}

	// Try to find user by email
	existingUser, err := s.userRepo.GetUserByEmail(ctx, googleUser.Email)
	if err == nil {
		// User exists with same email - link OAuth account
		oauth := &repository.OAuthAccount{
			UserID:     existingUser.ID,
			Provider:   "google",
			ProviderID: googleUser.Sub,
		}

		if err := s.userRepo.CreateOAuthAccount(ctx, oauth); err != nil {
			return nil, fmt.Errorf("failed to link oauth account: %w", err)
		}

		return existingUser, nil
	}

	// User doesn't exist - create new user
	if err != repository.ErrUserNotFound {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Create new user
	user := &repository.User{
		Email:         googleUser.Email,
		EmailVerified: googleUser.EmailVerified,
		Role:          "student", // Default role
		FullName:      googleUser.Name,
		AvatarURL:     googleUser.Picture,
	}

	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create OAuth account
	oauth := &repository.OAuthAccount{
		UserID:     user.ID,
		Provider:   "google",
		ProviderID: googleUser.Sub,
	}

	if err := s.userRepo.CreateOAuthAccount(ctx, oauth); err != nil {
		return nil, fmt.Errorf("failed to create oauth account: %w", err)
	}

	return user, nil
}

// GenerateTokens generates access and refresh tokens for a user
func (s *AuthService) GenerateTokens(ctx context.Context, user *repository.User) (*TokenPair, error) {
	// Generate access token (JWT)
	expiryHours := 24
	accessToken, err := auth.GenerateJWT(
		user.ID,
		user.Email,
		user.Role,
		s.jwtSecret,
		time.Duration(expiryHours)*time.Hour,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt: %w", err)
	}

	// Generate refresh token (random string)
	refreshToken, err := generateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Hash refresh token for storage
	hashedToken, err := hashToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Create session
	session := &repository.Session{
		UserID:       user.ID,
		RefreshToken: hashedToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Warning: failed to update last login: %v\n", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Return unhashed token to client
		ExpiresIn:    int64(expiryHours * 3600),
	}, nil
}

// ValidateAccessToken validates a JWT access token and returns claims
func (s *AuthService) ValidateAccessToken(accessToken string) (*auth.Claims, error) {
	claims, err := auth.ValidateJWT(accessToken, s.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	return claims, nil
}

// RefreshTokens generates new tokens using a refresh token
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Hash the refresh token to match database
	hashedToken, err := hashToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash refresh token: %w", err)
	}

	// Get session by refresh token
	session, err := s.sessionRepo.GetSessionByToken(ctx, hashedToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get user
	user, err := s.userRepo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Delete old session (token rotation)
	if err := s.sessionRepo.DeleteSession(ctx, session.ID); err != nil {
		return nil, fmt.Errorf("failed to delete old session: %w", err)
	}

	// Generate new tokens
	return s.GenerateTokens(ctx, user)
}

// Logout logs out a user by deleting their session
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if err := s.sessionRepo.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	return nil
}

// LogoutAllDevices logs out a user from all devices
func (s *AuthService) LogoutAllDevices(ctx context.Context, userID string) error {
	if err := s.sessionRepo.DeleteUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to logout from all devices: %w", err)
	}

	return nil
}

// Helper functions

// generateRandomToken generates a cryptographically secure random token
func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// hashToken hashes a token using bcrypt for storage
func hashToken(token string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}
