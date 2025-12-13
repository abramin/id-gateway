package admin

import (
	"context"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/models"
)

// UserStore defines the interface for user storage operations
type UserStore interface {
	ListAll(ctx context.Context) (map[string]*models.User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// SessionStore defines the interface for session storage operations
type SessionStore interface {
	ListAll(ctx context.Context) (map[string]*models.Session, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
}

// Service provides admin-level operations for monitoring and management
type Service struct {
	users    UserStore
	sessions SessionStore
	audit    audit.Store
}

// NewService creates a new admin service
func NewService(users UserStore, sessions SessionStore, auditStore audit.Store) *Service {
	return &Service{
		users:    users,
		sessions: sessions,
		audit:    auditStore,
	}
}

// Stats contains overall system statistics
type Stats struct {
	TotalUsers     int       `json:"total_users"`
	ActiveSessions int       `json:"active_sessions"`
	VCsIssued      int       `json:"vcs_issued"`
	DecisionsMade  int       `json:"decisions_made"`
	Timestamp      time.Time `json:"timestamp"`
}

// UserInfo contains user information with session details
type UserInfo struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	SessionCount int       `json:"session_count"`
	LastActive   time.Time `json:"last_active"`
	Verified     bool      `json:"verified"`
}

// GetStats returns overall system statistics
func (s *Service) GetStats(ctx context.Context) (*Stats, error) {
	users, err := s.users.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	sessions, err := s.sessions.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	// Count active (non-expired) sessions
	activeSessions := 0
	now := time.Now()
	for _, session := range sessions {
		if session.ExpiresAt.After(now) {
			activeSessions++
		}
	}

	// Get audit events for VC and decision counts
	events, err := s.audit.ListAll(ctx)
	if err != nil {
		// Don't fail if audit is unavailable
		events = []audit.Event{}
	}

	vcsIssued := 0
	decisionsMade := 0
	for _, event := range events {
		if event.Action == "vc_issued" {
			vcsIssued++
		}
		if event.Action == "decision_made" {
			decisionsMade++
		}
	}

	return &Stats{
		TotalUsers:     len(users),
		ActiveSessions: activeSessions,
		VCsIssued:      vcsIssued,
		DecisionsMade:  decisionsMade,
		Timestamp:      time.Now(),
	}, nil
}

// GetAllUsers returns all users with their session information
func (s *Service) GetAllUsers(ctx context.Context) ([]*UserInfo, error) {
	users, err := s.users.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	var userInfos []*UserInfo
	for _, user := range users {
		sessions, err := s.sessions.ListByUser(ctx, user.ID)
		if err != nil {
			// If we can't get sessions, continue with 0 count
			sessions = []*models.Session{}
		}

		// Find most recent session activity
		var lastActive time.Time
		for _, session := range sessions {
			if session.CreatedAt.After(lastActive) {
				lastActive = session.CreatedAt
			}
		}

		userInfos = append(userInfos, &UserInfo{
			ID:           user.ID,
			Email:        user.Email,
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			SessionCount: len(sessions),
			LastActive:   lastActive,
			Verified:     user.Verified,
		})
	}

	return userInfos, nil
}

// GetRecentAuditEvents returns recent audit events across all users
func (s *Service) GetRecentAuditEvents(ctx context.Context, limit int) ([]audit.Event, error) {
	return s.audit.ListRecent(ctx, limit)
}
