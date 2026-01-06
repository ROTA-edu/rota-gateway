package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ROTA-edu/rota-gateway/internal/auth"
	"github.com/ROTA-edu/rota-gateway/internal/repository"
	"github.com/ROTA-edu/rota-gateway/internal/service"
	"golang.org/x/oauth2"
)

// AuthService interface for dependency injection
type AuthService interface {
	GetOrCreateUserFromGoogle(ctx context.Context, googleUser *service.GoogleUserInfo) (*repository.User, error)
	GenerateTokens(ctx context.Context, user *repository.User) (*service.TokenPair, error)
	ValidateAccessToken(accessToken string) (*auth.Claims, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*service.TokenPair, error)
	Logout(ctx context.Context, sessionID string) error
	LogoutAllDevices(ctx context.Context, userID string) error
}

// GoogleOAuthProvider interface for dependency injection
type GoogleOAuthProvider interface {
	GenerateAuthURL(state string) string
	ExchangeCode(code string) (*oauth2.Token, error)
	GetUserInfo(accessToken string) (*auth.GoogleProfile, error)
}

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService AuthService
	googleOAuth *auth.GoogleOAuth
	stateStorage auth.StateStorage
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService AuthService, googleOAuth *auth.GoogleOAuth) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		googleOAuth:  googleOAuth,
		stateStorage: auth.NewInMemoryStateStorage(),
	}
}

// GoogleLogin initiates Google OAuth flow
// GET /auth/google/login
func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state for CSRF protection
	state, err := auth.GenerateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state for validation
	h.stateStorage.Store(state)

	// Generate Google OAuth URL
	authURL := h.googleOAuth.GenerateAuthURL(state)

	// Redirect to Google
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleCallback handles Google OAuth callback
// GET /auth/google/callback
func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get code and state from query params
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate inputs
	if code == "" {
		h.sendError(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	if state == "" {
		h.sendError(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	// Validate state (CSRF protection)
	if !h.stateStorage.Validate(state) {
		h.sendError(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := h.googleOAuth.ExchangeCode(code)
	if err != nil {
		h.sendError(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusBadRequest)
		return
	}

	// Get user info from Google
	googleProfile, err := h.googleOAuth.GetUserInfo(token.AccessToken)
	if err != nil {
		h.sendError(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert GoogleProfile to GoogleUserInfo
	googleUserInfo := &service.GoogleUserInfo{
		Email:         googleProfile.Email,
		EmailVerified: googleProfile.EmailVerified,
		Name:          googleProfile.Name,
		Picture:       googleProfile.Picture,
		Sub:           googleProfile.GoogleID,
	}

	// Get or create user
	user, err := h.authService.GetOrCreateUserFromGoogle(ctx, googleUserInfo)
	if err != nil {
		h.sendError(w, fmt.Sprintf("Failed to get or create user: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate tokens
	tokens, err := h.authService.GenerateTokens(ctx, user)
	if err != nil {
		h.sendError(w, fmt.Sprintf("Failed to generate tokens: %v", err), http.StatusInternalServerError)
		return
	}

	// Return tokens as JSON
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_in":    tokens.ExpiresIn,
		"token_type":    "Bearer",
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

// RefreshToken refreshes access token using refresh token
// POST /auth/refresh
// Body: {"refresh_token": "..."}
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		h.sendError(w, "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Refresh tokens
	tokens, err := h.authService.RefreshTokens(ctx, req.RefreshToken)
	if err != nil {
		if err == repository.ErrSessionNotFound || err == repository.ErrSessionExpired {
			h.sendError(w, "Invalid or expired refresh token", http.StatusUnauthorized)
			return
		}
		h.sendError(w, fmt.Sprintf("Failed to refresh tokens: %v", err), http.StatusInternalServerError)
		return
	}

	// Return new tokens
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_in":    tokens.ExpiresIn,
		"token_type":    "Bearer",
	})
}

// Logout logs out a user by invalidating their session
// POST /auth/logout
// Body: {"session_id": "..."}
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		h.sendError(w, "session_id is required", http.StatusBadRequest)
		return
	}

	// Logout
	if err := h.authService.Logout(ctx, req.SessionID); err != nil {
		h.sendError(w, fmt.Sprintf("Failed to logout: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success
	h.sendJSON(w, http.StatusOK, map[string]interface{}{
		"message": "logged out successfully",
	})
}

// Helper functions

func (h *AuthHandler) sendJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) sendError(w http.ResponseWriter, message string, statusCode int) {
	h.sendJSON(w, statusCode, map[string]interface{}{
		"error": message,
	})
}
