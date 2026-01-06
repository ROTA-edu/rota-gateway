package auth

import (
	"testing"
	"time"
)

// TestGenerateJWT tests JWT token generation
func TestGenerateJWT(t *testing.T) {
	tests := []struct {
		name      string
		userID    string
		email     string
		role      string
		secret    string
		expiry    time.Duration
		wantError bool
	}{
		{
			name:      "valid token generation",
			userID:    "user123",
			email:     "test@example.com",
			role:      "student",
			secret:    "test-secret-key-min-32-chars!!",
			expiry:    time.Hour,
			wantError: false,
		},
		{
			name:      "teacher role token",
			userID:    "teacher456",
			email:     "teacher@example.com",
			role:      "teacher",
			secret:    "test-secret-key-min-32-chars!!",
			expiry:    time.Hour * 24,
			wantError: false,
		},
		{
			name:      "empty user ID should fail",
			userID:    "",
			email:     "test@example.com",
			role:      "student",
			secret:    "test-secret-key-min-32-chars!!",
			expiry:    time.Hour,
			wantError: true,
		},
		{
			name:      "empty email should fail",
			userID:    "user123",
			email:     "",
			role:      "student",
			secret:    "test-secret-key-min-32-chars!!",
			expiry:    time.Hour,
			wantError: true,
		},
		{
			name:      "invalid role should fail",
			userID:    "user123",
			email:     "test@example.com",
			role:      "admin", // Only student/teacher allowed
			secret:    "test-secret-key-min-32-chars!!",
			expiry:    time.Hour,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateJWT(tt.userID, tt.email, tt.role, tt.secret, tt.expiry)

			if tt.wantError {
				if err == nil {
					t.Errorf("GenerateJWT() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateJWT() unexpected error: %v", err)
				return
			}

			if token == "" {
				t.Error("GenerateJWT() returned empty token")
			}
		})
	}
}

// TestValidateJWT tests JWT token validation
func TestValidateJWT(t *testing.T) {
	secret := "test-secret-key-min-32-chars!!"
	userID := "user123"
	email := "test@example.com"
	role := "student"

	// Generate a valid token
	token, err := GenerateJWT(userID, email, role, secret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token for test: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		secret    string
		wantError bool
	}{
		{
			name:      "valid token",
			token:     token,
			secret:    secret,
			wantError: false,
		},
		{
			name:      "invalid secret",
			token:     token,
			secret:    "wrong-secret-key",
			wantError: true,
		},
		{
			name:      "malformed token",
			token:     "not.a.token",
			secret:    secret,
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			secret:    secret,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateJWT(tt.token, tt.secret)

			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateJWT() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateJWT() unexpected error: %v", err)
				return
			}

			if claims == nil {
				t.Error("ValidateJWT() returned nil claims")
				return
			}

			if claims.UserID != userID {
				t.Errorf("ValidateJWT() userID = %v, want %v", claims.UserID, userID)
			}

			if claims.Email != email {
				t.Errorf("ValidateJWT() email = %v, want %v", claims.Email, email)
			}

			if claims.Role != role {
				t.Errorf("ValidateJWT() role = %v, want %v", claims.Role, role)
			}
		})
	}
}

// TestJWTExpiry tests that expired tokens are rejected
func TestJWTExpiry(t *testing.T) {
	secret := "test-secret-key-min-32-chars!!"

	// Generate a token that expires immediately
	token, err := GenerateJWT("user123", "test@example.com", "student", secret, time.Nanosecond)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Wait for token to expire
	time.Sleep(time.Millisecond * 10)

	// Attempt to validate expired token
	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("ValidateJWT() should reject expired token")
	}
}

// TestRefreshToken tests refresh token generation and validation
func TestRefreshToken(t *testing.T) {
	secret := "test-secret-key-min-32-chars!!"
	userID := "user123"

	// Generate refresh token
	refreshToken, err := GenerateRefreshToken(userID, secret)
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error: %v", err)
	}

	if refreshToken == "" {
		t.Error("GenerateRefreshToken() returned empty token")
	}

	// Validate refresh token
	extractedUserID, err := ValidateRefreshToken(refreshToken, secret)
	if err != nil {
		t.Errorf("ValidateRefreshToken() error: %v", err)
	}

	if extractedUserID != userID {
		t.Errorf("ValidateRefreshToken() userID = %v, want %v", extractedUserID, userID)
	}
}
