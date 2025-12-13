package seeder

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"credo/internal/audit"
	"credo/internal/auth/models"
)

// UserStore defines methods for seeding users
type UserStore interface {
	Save(ctx context.Context, user *models.User) error
}

// SessionStore defines methods for seeding sessions
type SessionStore interface {
	Save(ctx context.Context, session *models.Session) error
}

// AuditStore defines methods for seeding audit events
type AuditStore interface {
	Append(ctx context.Context, event audit.Event) error
}

// Seeder populates in-memory stores with demo data
type Seeder struct {
	users    UserStore
	sessions SessionStore
	audit    AuditStore
	logger   *slog.Logger
}

// New creates a new seeder
func New(users UserStore, sessions SessionStore, auditStore AuditStore, logger *slog.Logger) *Seeder {
	return &Seeder{
		users:    users,
		sessions: sessions,
		audit:    auditStore,
		logger:   logger,
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
			ID:        uuid.New(),
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
		status        string
		createdOffset time.Duration
		expiryOffset  time.Duration
		codeUsed      bool
	}{
		{0, "active", -10 * time.Minute, 50 * time.Minute, false},
		{0, "active", -2 * time.Hour, -1 * time.Hour, true},
		{1, "active", -30 * time.Minute, 30 * time.Minute, false},
		{2, "active", -1 * time.Hour, 23 * time.Hour, false},
		{3, "active", -5 * time.Hour, -4 * time.Hour, true},
		{4, "active", -15 * time.Minute, 45 * time.Minute, false},
	}

	for _, sess := range sessions {
		if sess.userIdx >= len(users) {
			continue
		}

		session := &models.Session{
			ID:             uuid.New(),
			UserID:         users[sess.userIdx].ID,
			Code:           fmt.Sprintf("authz_%s", uuid.New().String()[:12]),
			CodeExpiresAt:  now.Add(10 * time.Minute),
			CodeUsed:       sess.codeUsed,
			ClientID:       "demo-client",
			RedirectURI:    "http://localhost:3000/demo/callback.html",
			RequestedScope: []string{"openid", "profile"},
			Status:         sess.status,
			CreatedAt:      now.Add(sess.createdOffset),
			ExpiresAt:      now.Add(sess.expiryOffset),
		}

		if err := s.sessions.Save(ctx, session); err != nil {
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
			UserID:    users[e.userIdx].ID.String(),
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
