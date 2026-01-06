package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	// ErrInvalidCode is returned when OAuth code is invalid
	ErrInvalidCode = errors.New("invalid authorization code")
	// ErrUnverifiedEmail is returned when email is not verified
	ErrUnverifiedEmail = errors.New("email not verified by Google")
	// ErrMissingEmail is returned when email is missing from profile
	ErrMissingEmail = errors.New("email missing from Google profile")
	// ErrInvalidState is returned when OAuth state is invalid
	ErrInvalidState = errors.New("invalid or expired state parameter")
)

// GoogleOAuth handles Google OAuth 2.0 flow
type GoogleOAuth struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	config       *oauth2.Config
}

// GoogleProfile represents user info from Google
type GoogleProfile struct {
	GoogleID      string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// StateStorage stores and validates OAuth state parameters
type StateStorage interface {
	Store(state string)
	Validate(state string) bool
}

// NewGoogleOAuth creates a new Google OAuth handler
func NewGoogleOAuth(clientID, clientSecret, redirectURL string) *GoogleOAuth {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"openid",
		},
		Endpoint: google.Endpoint,
	}

	return &GoogleOAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		config:       config,
	}
}

// GenerateAuthURL generates Google OAuth URL with state parameter
func (g *GoogleOAuth) GenerateAuthURL(state string) string {
	return g.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges authorization code for tokens
func (g *GoogleOAuth) ExchangeCode(code string) (*oauth2.Token, error) {
	if code == "" {
		return nil, ErrInvalidCode
	}

	ctx := context.Background()
	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}

// GetUserInfo fetches user information from Google
func (g *GoogleOAuth) GetUserInfo(accessToken string) (*GoogleProfile, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Google API error %d: %s", resp.StatusCode, string(body))
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return ParseGoogleProfile(userInfo)
}

// ParseGoogleProfile parses Google user info into GoogleProfile
func ParseGoogleProfile(tokenInfo map[string]interface{}) (*GoogleProfile, error) {
	// Extract email
	email, ok := tokenInfo["email"].(string)
	if !ok || email == "" {
		return nil, ErrMissingEmail
	}

	// Verify email is verified
	emailVerified, _ := tokenInfo["email_verified"].(bool)
	if !emailVerified {
		return nil, ErrUnverifiedEmail
	}

	profile := &GoogleProfile{
		Email:         email,
		EmailVerified: emailVerified,
	}

	// Optional fields
	if googleID, ok := tokenInfo["sub"].(string); ok {
		profile.GoogleID = googleID
	}
	if name, ok := tokenInfo["name"].(string); ok {
		profile.Name = name
	}
	if picture, ok := tokenInfo["picture"].(string); ok {
		profile.Picture = picture
	}

	return profile, nil
}

// GenerateState generates a cryptographically secure random state
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}

	// Use URL-safe base64 encoding
	state := base64.URLEncoding.EncodeToString(b)
	// Remove padding
	state = strings.TrimRight(state, "=")

	return state, nil
}

// InMemoryStateStorage is a simple in-memory state storage
// For production, use Redis or database
type InMemoryStateStorage struct {
	mu     sync.RWMutex
	states map[string]time.Time
}

// NewInMemoryStateStorage creates a new in-memory state storage
func NewInMemoryStateStorage() *InMemoryStateStorage {
	storage := &InMemoryStateStorage{
		states: make(map[string]time.Time),
	}

	// Cleanup expired states every 5 minutes
	go storage.cleanup()

	return storage
}

// Store stores a state with expiration
func (s *InMemoryStateStorage) Store(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// States expire after 10 minutes
	s.states[state] = time.Now().Add(10 * time.Minute)
}

// Validate validates and consumes a state (one-time use)
func (s *InMemoryStateStorage) Validate(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, exists := s.states[state]
	if !exists {
		return false
	}

	// Check if expired
	if time.Now().After(expiry) {
		delete(s.states, state)
		return false
	}

	// Consume the state (delete after use)
	delete(s.states, state)
	return true
}

// cleanup removes expired states
func (s *InMemoryStateStorage) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for state, expiry := range s.states {
			if now.After(expiry) {
				delete(s.states, state)
			}
		}
		s.mu.Unlock()
	}
}

// BuildGoogleAuthURL is a helper to build the full OAuth URL
func BuildGoogleAuthURL(clientID, redirectURL, state string) string {
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURL)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	params.Add("access_type", "offline")

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}
