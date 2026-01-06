package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ROTA-edu/rota-gateway/internal/database"
)

// Session errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// Session represents a session in the auth.sessions table
type Session struct {
	ID           string
	UserID       string
	RefreshToken string // Hashed refresh token
	DeviceInfo   string // JSON string
	IPAddress    string
	UserAgent    string
	CreatedAt    time.Time
	LastUsedAt   time.Time
	ExpiresAt    time.Time
}

// SessionRepository handles session-related database operations
type SessionRepository struct {
	db *database.Postgres
}

// NewSessionRepository creates a new SessionRepository
func NewSessionRepository(db *database.Postgres) *SessionRepository {
	return &SessionRepository{db: db}
}

// CreateSession creates a new session in the database
func (r *SessionRepository) CreateSession(ctx context.Context, session *Session) error {
	query := `
		INSERT INTO auth.sessions (user_id, refresh_token, device_info, ip_address, user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, last_used_at
	`

	err := r.db.DB.QueryRowContext(
		ctx,
		query,
		session.UserID,
		session.RefreshToken,
		session.DeviceInfo,
		session.IPAddress,
		session.UserAgent,
		session.ExpiresAt,
	).Scan(&session.ID, &session.CreatedAt, &session.LastUsedAt)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSessionByToken retrieves a session by refresh token
// Returns ErrSessionNotFound if not found
// Returns ErrSessionExpired if session is expired
func (r *SessionRepository) GetSessionByToken(ctx context.Context, refreshToken string) (*Session, error) {
	query := `
		SELECT id, user_id, refresh_token, device_info, ip_address, user_agent, created_at, last_used_at, expires_at
		FROM auth.sessions
		WHERE refresh_token = $1
	`

	session := &Session{}
	err := r.db.DB.QueryRowContext(ctx, query, refreshToken).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshToken,
		&session.DeviceInfo,
		&session.IPAddress,
		&session.UserAgent,
		&session.CreatedAt,
		&session.LastUsedAt,
		&session.ExpiresAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session by token: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// DeleteSession deletes a session by ID
func (r *SessionRepository) DeleteSession(ctx context.Context, sessionID string) error {
	query := `DELETE FROM auth.sessions WHERE id = $1`

	result, err := r.db.DB.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

// DeleteUserSessions deletes all sessions for a user (logout from all devices)
func (r *SessionRepository) DeleteUserSessions(ctx context.Context, userID string) error {
	query := `DELETE FROM auth.sessions WHERE user_id = $1`

	_, err := r.db.DB.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	return nil
}

// UpdateLastUsed updates the last_used_at timestamp for a session
func (r *SessionRepository) UpdateLastUsed(ctx context.Context, sessionID string) error {
	query := `
		UPDATE auth.sessions
		SET last_used_at = NOW()
		WHERE id = $1
	`

	result, err := r.db.DB.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

// CleanupExpiredSessions removes all expired sessions from the database
// Returns the number of sessions deleted
func (r *SessionRepository) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	query := `DELETE FROM auth.sessions WHERE expires_at < NOW()`

	result, err := r.db.DB.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}
