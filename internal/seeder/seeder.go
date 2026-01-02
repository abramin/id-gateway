package seeder

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/audit"
)

// UserStore defines methods for seeding users
type UserStore interface {
	Save(ctx context.Context, user *models.User) error
}

// SessionStore defines methods for seeding sessions
type SessionStore interface {
	Create(ctx context.Context, session *models.Session) error
}

// AuthorizationCodeStore defines methods for seeding auth codes
type AuthorizationCodeStore interface {
	Create(ctx context.Context, authCode *models.AuthorizationCodeRecord) error
}

// RefreshTokenStore defines methods for seeding refresh tokens
type RefreshTokenStore interface {
	Create(ctx context.Context, token *models.RefreshTokenRecord) error
}

// AuditStore defines methods for seeding audit events
type AuditStore interface {
	Append(ctx context.Context, event audit.Event) error
}

// Seeder populates stores with demo data.
type Seeder struct {
	users         UserStore
	sessions      SessionStore
	authCodes     AuthorizationCodeStore
	refreshTokens RefreshTokenStore
	audit         AuditStore
	logger        *slog.Logger
}

// New creates a new seeder
func New(users UserStore, sessions SessionStore, authCodes AuthorizationCodeStore, refreshTokens RefreshTokenStore, auditStore AuditStore, logger *slog.Logger) *Seeder {
	return &Seeder{
		users:         users,
		sessions:      sessions,
		authCodes:     authCodes,
		refreshTokens: refreshTokens,
		audit:         auditStore,
		logger:        logger,
	}
}

// SeedAll populates all stores with demo data
func (s *Seeder) SeedAll(ctx context.Context) error {
	s.logger.Info("seeding demo data...")

	// Seed users
	users, err := s.seedUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to seed users: %w", err)
	}

	// Seed sessions for some users
	if err := s.seedSessions(ctx, users); err != nil {
		return fmt.Errorf("failed to seed sessions: %w", err)
	}

	// Seed audit events
	if err := s.seedAuditEvents(ctx, users); err != nil {
		return fmt.Errorf("failed to seed audit events: %w", err)
	}

	s.logger.Info("demo data seeded successfully",
		"users", len(users),
	)

	return nil
}

func (s *Seeder) seedUsers(ctx context.Context) ([]*models.User, error) {
	demoUsers := []struct {
		email     string
		firstName string
		lastName  string
		verified  bool
	}{
		{"alice@example.com", "Alice", "Anderson", true},
		{"bob@example.com", "Bob", "Brown", true},
		{"charlie@example.com", "Charlie", "Chen", true},
		{"diana@example.com", "Diana", "Davis", true},
		{"eve@example.com", "Eve", "Evans", false},
		{"frank@example.com", "Frank", "Foster", true},
		{"grace@example.com", "Grace", "Garcia", true},
		{"henry@example.com", "Henry", "Harris", false},
	}

	var users []*models.User
	for _, u := range demoUsers {
		user := &models.User{
			ID:        id.UserID(uuid.New()),
			Email:     u.email,
			FirstName: u.firstName,
			LastName:  u.lastName,
			Verified:  u.verified,
		}

		if err := s.users.Save(ctx, user); err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (s *Seeder) seedSessions(ctx context.Context, users []*models.User) error {
	now := time.Now()

	// Create sessions for first 5 users (some active, some expired)
	sessions := []struct {
		userIdx       int
		status        models.SessionStatus
		createdOffset time.Duration
		expiryOffset  time.Duration
		codeUsed      bool
		tokenUsed     bool
	}{
		{0, models.SessionStatusActive, -10 * time.Minute, 50 * time.Minute, true, false},
		{0, models.SessionStatusRevoked, -2 * time.Hour, -1 * time.Hour, true, true},
		{1, models.SessionStatusActive, -30 * time.Minute, 30 * time.Minute, true, false},
		{2, models.SessionStatusActive, -1 * time.Hour, 23 * time.Hour, true, false},
		{3, models.SessionStatusRevoked, -5 * time.Hour, -4 * time.Hour, true, true},
		{4, models.SessionStatusPendingConsent, -15 * time.Minute, 45 * time.Minute, false, false},
	}

	for _, sess := range sessions {
		if sess.userIdx >= len(users) {
			continue
		}

		createdAt := now.Add(sess.createdOffset)
		expiresAt := now.Add(sess.expiryOffset)
		lastSeenAt := createdAt.Add(2 * time.Minute)
		var revokedAt *time.Time
		if sess.status == models.SessionStatusRevoked {
			revoked := lastSeenAt
			revokedAt = &revoked
		}

		session := &models.Session{
			ID:                  id.SessionID(uuid.New()),
			UserID:              users[sess.userIdx].ID,
			ClientID:            id.ClientID(uuid.New()),
			RequestedScope:      []string{"openid", "profile"},
			Status:              sess.status,
			DeviceID:            fmt.Sprintf("device_%s", uuid.New().String()),
			DeviceDisplayName:   "Chrome on macOS",
			ApproximateLocation: "San Francisco, US",
			CreatedAt:           createdAt,
			ExpiresAt:           expiresAt,
			LastSeenAt:          lastSeenAt,
			RevokedAt:           revokedAt,
		}

		if err := s.sessions.Create(ctx, session); err != nil {
			return err
		}

		authCode := &models.AuthorizationCodeRecord{
			ID:          uuid.New(),
			Code:        fmt.Sprintf("authz_%s", uuid.New().String()[:12]),
			SessionID:   session.ID,
			RedirectURI: "http://localhost:3000/demo/callback.html",
			ExpiresAt:   createdAt.Add(10 * time.Minute),
			Used:        sess.codeUsed,
			CreatedAt:   createdAt,
		}
		if err := s.authCodes.Create(ctx, authCode); err != nil {
			return err
		}

		if sess.status == "pending_consent" {
			continue
		}

		lastRefreshedAt := lastSeenAt.Add(1 * time.Minute)
		session.LastRefreshedAt = &lastRefreshedAt
		refreshToken := &models.RefreshTokenRecord{
			ID:              uuid.New(),
			Token:           fmt.Sprintf("ref_%s", uuid.New().String()),
			SessionID:       session.ID,
			ExpiresAt:       createdAt.Add(30 * 24 * time.Hour),
			Used:            sess.tokenUsed,
			LastRefreshedAt: &lastRefreshedAt,
			CreatedAt:       createdAt,
		}
		if err := s.refreshTokens.Create(ctx, refreshToken); err != nil {
			return err
		}
	}

	return nil
}

func (s *Seeder) seedAuditEvents(ctx context.Context, users []*models.User) error {
	now := time.Now()

	events := []struct {
		userIdx  int
		action   string
		purpose  string
		decision string
		offset   time.Duration
	}{
		{0, "session_created", "login", "granted", -10 * time.Minute},
		{0, "consent_granted", "registry_check", "granted", -9 * time.Minute},
		{0, "decision_made", "age_verification", "pass", -8 * time.Minute},
		{0, "vc_issued", "age_credential", "issued", -7 * time.Minute},
		{1, "session_created", "login", "granted", -30 * time.Minute},
		{1, "consent_granted", "vc_issuance", "granted", -29 * time.Minute},
		{1, "vc_issued", "age_credential", "issued", -28 * time.Minute},
		{2, "session_created", "login", "granted", -1 * time.Hour},
		{2, "decision_made", "sanctions_screening", "pass", -59 * time.Minute},
		{3, "session_created", "login", "granted", -2 * time.Hour},
		{3, "consent_revoked", "registry_check", "revoked", -119 * time.Minute},
		{4, "decision_made", "age_verification", "fail", -15 * time.Minute},
		{5, "session_created", "login", "granted", -3 * time.Hour},
		{5, "vc_issued", "identity_credential", "issued", -179 * time.Minute},
	}

	for _, e := range events {
		if e.userIdx >= len(users) {
			continue
		}

		event := audit.Event{
			Timestamp: now.Add(e.offset),
			UserID:    users[e.userIdx].ID,
			Action:    e.action,
			Purpose:   e.purpose,
			Decision:  e.decision,
		}

		if err := s.audit.Append(ctx, event); err != nil {
			return err
		}
	}

	return nil
}
