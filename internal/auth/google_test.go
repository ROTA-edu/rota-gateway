package auth

import (
	"net/url"
	"testing"
)

// TestGenerateAuthURL tests OAuth URL generation
func TestGenerateAuthURL(t *testing.T) {
	oauth := NewGoogleOAuth(
		"test-client-id",
		"test-client-secret",
		"http://localhost:8080/auth/callback",
	)

	tests := []struct {
		name  string
		state string
	}{
		{
			name:  "valid state",
			state: "random-state-string",
		},
		{
			name:  "long state",
			state: "very-long-state-string-with-lots-of-characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL := oauth.GenerateAuthURL(tt.state)

			parsedURL, err := url.Parse(authURL)
			if err != nil {
				t.Errorf("GenerateAuthURL() returned invalid URL: %v", err)
				return
			}

			// Verify URL components
			if parsedURL.Scheme != "https" {
				t.Error("Auth URL should use HTTPS")
			}

			if parsedURL.Host != "accounts.google.com" {
				t.Errorf("Auth URL host = %v, want accounts.google.com", parsedURL.Host)
			}

			query := parsedURL.Query()

			if query.Get("client_id") != oauth.ClientID {
				t.Errorf("client_id = %v, want %v", query.Get("client_id"), oauth.ClientID)
			}

			if query.Get("redirect_uri") != oauth.RedirectURL {
				t.Errorf("redirect_uri = %v, want %v", query.Get("redirect_uri"), oauth.RedirectURL)
			}

			if query.Get("state") != tt.state {
				t.Errorf("state = %v, want %v", query.Get("state"), tt.state)
			}

			if query.Get("response_type") != "code" {
				t.Error("response_type should be 'code'")
			}

			scopes := query.Get("scope")
			if scopes == "" {
				t.Error("scope should not be empty")
			}
		})
	}
}

// TestGenerateState tests secure state generation
func TestGenerateState(t *testing.T) {
	// Generate multiple states
	states := make(map[string]bool)
	for i := 0; i < 100; i++ {
		state, err := GenerateState()
		if err != nil {
			t.Errorf("GenerateState() error: %v", err)
			continue
		}

		if len(state) < 32 {
			t.Errorf("GenerateState() length = %d, want >= 32", len(state))
		}

		// Check for duplicates
		if states[state] {
			t.Error("GenerateState() produced duplicate state")
		}
		states[state] = true
	}
}

// TestValidateState tests state validation
func TestValidateState(t *testing.T) {
	storage := NewInMemoryStateStorage()

	originalState := "test-state-123"
	storage.Store(originalState)

	tests := []struct {
		name      string
		state     string
		wantValid bool
	}{
		{
			name:      "valid state",
			state:     originalState,
			wantValid: true,
		},
		{
			name:      "invalid state",
			state:     "wrong-state",
			wantValid: false,
		},
		{
			name:      "empty state",
			state:     "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := storage.Validate(tt.state)
			if valid != tt.wantValid {
				t.Errorf("ValidateState() = %v, want %v", valid, tt.wantValid)
			}

			// State should be consumed (one-time use)
			if tt.wantValid {
				validAgain := storage.Validate(tt.state)
				if validAgain {
					t.Error("State should be consumed after first validation")
				}
			}
		})
	}
}

// TestExchangeCodeForToken tests the OAuth code exchange flow
func TestExchangeCodeForToken(t *testing.T) {
	// This is a mock test - real implementation will use httptest
	// to mock Google's OAuth endpoints

	oauth := NewGoogleOAuth(
		"test-client-id",
		"test-client-secret",
		"http://localhost:8080/auth/callback",
	)

	t.Run("exchange with invalid code should fail", func(t *testing.T) {
		_, err := oauth.ExchangeCode("")
		if err == nil {
			t.Error("ExchangeCode() with empty code should fail")
		}
	})
}

// TestParseGoogleProfile tests parsing of Google user info
func TestParseGoogleProfile(t *testing.T) {
	tests := []struct {
		name      string
		tokenInfo map[string]interface{}
		wantError bool
	}{
		{
			name: "valid profile",
			tokenInfo: map[string]interface{}{
				"sub":            "google-user-id-123",
				"email":          "test@example.com",
				"email_verified": true,
				"name":           "Test User",
				"picture":        "https://example.com/photo.jpg",
			},
			wantError: false,
		},
		{
			name: "unverified email should fail",
			tokenInfo: map[string]interface{}{
				"sub":            "google-user-id-123",
				"email":          "test@example.com",
				"email_verified": false,
			},
			wantError: true,
		},
		{
			name: "missing email should fail",
			tokenInfo: map[string]interface{}{
				"sub":            "google-user-id-123",
				"email_verified": true,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := ParseGoogleProfile(tt.tokenInfo)

			if tt.wantError {
				if err == nil {
					t.Error("ParseGoogleProfile() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseGoogleProfile() unexpected error: %v", err)
				return
			}

			if profile.GoogleID != tt.tokenInfo["sub"] {
				t.Errorf("GoogleID = %v, want %v", profile.GoogleID, tt.tokenInfo["sub"])
			}

			if profile.Email != tt.tokenInfo["email"] {
				t.Errorf("Email = %v, want %v", profile.Email, tt.tokenInfo["email"])
			}
		})
	}
}
