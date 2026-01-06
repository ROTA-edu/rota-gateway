package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/database"
	"github.com/lib/pq"
)

// Common errors
var (
	ErrUserNotFound         = errors.New("user not found")
	ErrOAuthAccountNotFound = errors.New("oauth account not found")
	ErrDuplicateEmail       = errors.New("duplicate email")
)

// User represents a user in the auth.users table
type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Role          string // "student", "teacher", "admin"
	FullName      string
	AvatarURL     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}

// OAuthAccount represents an OAuth account in auth.oauth_accounts table
type OAuthAccount struct {
	ID           string
	UserID       string
	Provider     string // "google", "apple", etc.
	ProviderID   string
	AccessToken  string
	RefreshToken string
	ExpiresAt    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserRepository handles user-related database operations
type UserRepository struct {
	db *database.Postgres
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *database.Postgres) *UserRepository {
	return &UserRepository{db: db}
}

// CreateUser creates a new user in the database
func (r *UserRepository) CreateUser(ctx context.Context, user *User) error {
	query := `
		INSERT INTO auth.users (email, email_verified, role, full_name, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at
	`

	err := r.db.DB.QueryRowContext(
		ctx,
		query,
		user.Email,
		user.EmailVerified,
		user.Role,
		user.FullName,
		user.AvatarURL,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		// Check for unique constraint violation (duplicate email)
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				return fmt.Errorf("%w: %s", ErrDuplicateEmail, user.Email)
			}
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByEmail retrieves a user by email
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, email_verified, role, full_name, avatar_url, created_at, updated_at, last_login_at
		FROM auth.users
		WHERE email = $1
	`

	user := &User{}
	err := r.db.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&user.Role,
		&user.FullName,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (r *UserRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT id, email, email_verified, role, full_name, avatar_url, created_at, updated_at, last_login_at
		FROM auth.users
		WHERE id = $1
	`

	user := &User{}
	err := r.db.DB.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.EmailVerified,
		&user.Role,
		&user.FullName,
		&user.AvatarURL,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	return user, nil
}

// UpdateLastLogin updates the last_login_at timestamp for a user
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	query := `
		UPDATE auth.users
		SET last_login_at = NOW()
		WHERE id = $1
	`

	result, err := r.db.DB.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// CreateOAuthAccount creates a new OAuth account linked to a user
func (r *UserRepository) CreateOAuthAccount(ctx context.Context, oauth *OAuthAccount) error {
	query := `
		INSERT INTO auth.oauth_accounts (user_id, provider, provider_id, access_token, refresh_token, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`

	err := r.db.DB.QueryRowContext(
		ctx,
		query,
		oauth.UserID,
		oauth.Provider,
		oauth.ProviderID,
		oauth.AccessToken,
		oauth.RefreshToken,
		oauth.ExpiresAt,
	).Scan(&oauth.ID, &oauth.CreatedAt, &oauth.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create oauth account: %w", err)
	}

	return nil
}

// GetOAuthAccount retrieves an OAuth account by provider and provider ID
func (r *UserRepository) GetOAuthAccount(ctx context.Context, provider, providerID string) (*OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_id, access_token, refresh_token, expires_at, created_at, updated_at
		FROM auth.oauth_accounts
		WHERE provider = $1 AND provider_id = $2
	`

	oauth := &OAuthAccount{}
	err := r.db.DB.QueryRowContext(ctx, query, provider, providerID).Scan(
		&oauth.ID,
		&oauth.UserID,
		&oauth.Provider,
		&oauth.ProviderID,
		&oauth.AccessToken,
		&oauth.RefreshToken,
		&oauth.ExpiresAt,
		&oauth.CreatedAt,
		&oauth.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrOAuthAccountNotFound
		}
		return nil, fmt.Errorf("failed to get oauth account: %w", err)
	}

	return oauth, nil
}
