package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"credo/internal/auth/models"
	id "credo/pkg/domain"
	"credo/pkg/platform/sentinel"
)

const (
	// Redis key prefixes for session data
	sessionKeyPrefix     = "session:"
	userSessionKeyPrefix = "user_sessions:"

	// maxSessionsPerUser caps the number of sessions loaded per user to prevent
	// unbounded memory growth. Sessions beyond this limit are not loaded.
	maxSessionsPerUser = 100

	// defaultSessionTTL is the fallback TTL when session expiry cannot be determined.
	defaultSessionTTL = 30 * 24 * time.Hour
)

// sessionJSON is the JSON-serializable representation of a Session.
// We use explicit JSON tags to control serialization format.
type sessionJSON struct {
	ID                    string   `json:"id"`
	UserID                string   `json:"user_id"`
	ClientID              string   `json:"client_id"`
	TenantID              string   `json:"tenant_id"`
	RequestedScope        []string `json:"requested_scope"`
	Status                string   `json:"status"`
	LastRefreshedAt       *int64   `json:"last_refreshed_at,omitempty"` // Unix nano
	LastAccessTokenJTI    string   `json:"last_access_token_jti"`
	DeviceID              string   `json:"device_id"`
	DeviceFingerprintHash string   `json:"device_fingerprint_hash"`
	DeviceDisplayName     string   `json:"device_display_name"`
	ApproximateLocation   string   `json:"approximate_location"`
	CreatedAt             int64    `json:"created_at"`           // Unix nano
	ExpiresAt             int64    `json:"expires_at"`           // Unix nano
	LastSeenAt            int64    `json:"last_seen_at"`         // Unix nano
	RevokedAt             *int64   `json:"revoked_at,omitempty"` // Unix nano
}

func sessionToJSON(s *models.Session) *sessionJSON {
	j := &sessionJSON{
		ID:                    uuid.UUID(s.ID).String(),
		UserID:                uuid.UUID(s.UserID).String(),
		ClientID:              uuid.UUID(s.ClientID).String(),
		TenantID:              uuid.UUID(s.TenantID).String(),
		RequestedScope:        s.RequestedScope,
		Status:                string(s.Status),
		LastAccessTokenJTI:    s.LastAccessTokenJTI,
		DeviceID:              s.DeviceID,
		DeviceFingerprintHash: s.DeviceFingerprintHash,
		DeviceDisplayName:     s.DeviceDisplayName,
		ApproximateLocation:   s.ApproximateLocation,
		CreatedAt:             s.CreatedAt.UnixNano(),
		ExpiresAt:             s.ExpiresAt.UnixNano(),
		LastSeenAt:            s.LastSeenAt.UnixNano(),
	}
	if s.LastRefreshedAt != nil {
		ts := s.LastRefreshedAt.UnixNano()
		j.LastRefreshedAt = &ts
	}
	if s.RevokedAt != nil {
		ts := s.RevokedAt.UnixNano()
		j.RevokedAt = &ts
	}
	return j
}

func sessionFromJSON(j *sessionJSON) (*models.Session, error) {
	sessionID, err := uuid.Parse(j.ID)
	if err != nil {
		return nil, fmt.Errorf("parse session id: %w", err)
	}
	userID, err := uuid.Parse(j.UserID)
	if err != nil {
		return nil, fmt.Errorf("parse user id: %w", err)
	}
	clientID, err := uuid.Parse(j.ClientID)
	if err != nil {
		return nil, fmt.Errorf("parse client id: %w", err)
	}
	tenantID, err := uuid.Parse(j.TenantID)
	if err != nil {
		return nil, fmt.Errorf("parse tenant id: %w", err)
	}

	s := &models.Session{
		ID:                    id.SessionID(sessionID),
		UserID:                id.UserID(userID),
		ClientID:              id.ClientID(clientID),
		TenantID:              id.TenantID(tenantID),
		RequestedScope:        j.RequestedScope,
		Status:                models.SessionStatus(j.Status),
		LastAccessTokenJTI:    j.LastAccessTokenJTI,
		DeviceID:              j.DeviceID,
		DeviceFingerprintHash: j.DeviceFingerprintHash,
		DeviceDisplayName:     j.DeviceDisplayName,
		ApproximateLocation:   j.ApproximateLocation,
		CreatedAt:             time.Unix(0, j.CreatedAt),
		ExpiresAt:             time.Unix(0, j.ExpiresAt),
		LastSeenAt:            time.Unix(0, j.LastSeenAt),
	}
	if j.LastRefreshedAt != nil {
		t := time.Unix(0, *j.LastRefreshedAt)
		s.LastRefreshedAt = &t
	}
	if j.RevokedAt != nil {
		t := time.Unix(0, *j.RevokedAt)
		s.RevokedAt = &t
	}
	return s, nil
}

// RedisStore persists sessions in Redis.
// This is the production-recommended implementation for distributed deployments
// where multiple instances need to share session state.
type RedisStore struct {
	client *redis.Client
}

// NewRedis constructs a Redis-backed session store.
func NewRedis(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func (s *RedisStore) sessionKey(sessionID id.SessionID) string {
	return sessionKeyPrefix + uuid.UUID(sessionID).String()
}

func (s *RedisStore) userSessionsKey(userID id.UserID) string {
	return userSessionKeyPrefix + uuid.UUID(userID).String()
}

// getOrComputeTTL retrieves the existing TTL for a key, falling back to computing
// from session expiry or using the default TTL.
func getOrComputeTTL(ctx context.Context, getter redis.Cmdable, key string, session *models.Session) time.Duration {
	ttl, err := getter.TTL(ctx, key).Result()
	if err == nil && ttl > 0 {
		return ttl
	}
	if remaining := time.Until(session.ExpiresAt); remaining > 0 {
		return remaining
	}
	return defaultSessionTTL
}

// deserializeSessionCmd extracts and deserializes a session from a Redis string command result.
// Returns nil if the command failed or the data is malformed.
func deserializeSessionCmd(cmd *redis.StringCmd) *models.Session {
	data, err := cmd.Result()
	if err != nil {
		return nil
	}
	var j sessionJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil
	}
	session, err := sessionFromJSON(&j)
	if err != nil {
		return nil
	}
	return session
}

func (s *RedisStore) Create(ctx context.Context, session *models.Session) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}

	data, err := json.Marshal(sessionToJSON(session))
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	key := s.sessionKey(session.ID)
	userKey := s.userSessionsKey(session.UserID)
	sessionIDStr := uuid.UUID(session.ID).String()

	// Calculate TTL from session expiry
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}

	// Use pipeline for atomic operations
	pipe := s.client.Pipeline()
	pipe.Set(ctx, key, data, ttl)
	// Add to user's session set (for ListByUser)
	pipe.SAdd(ctx, userKey, sessionIDStr)
	// Set expiry on the user sessions set too (cleanup)
	pipe.Expire(ctx, userKey, ttl+time.Hour) // Slightly longer to allow for cleanup

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (s *RedisStore) FindByID(ctx context.Context, sessionID id.SessionID) (*models.Session, error) {
	key := s.sessionKey(sessionID)
	data, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("find session by id: %w", err)
	}

	var j sessionJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return sessionFromJSON(&j)
}

func (s *RedisStore) ListByUser(ctx context.Context, userID id.UserID) ([]*models.Session, error) {
	userKey := s.userSessionsKey(userID)

	// Get session IDs for this user (capped to prevent unbounded memory growth)
	// Using SRandMember with count returns up to N distinct members
	sessionIDs, err := s.client.SRandMemberN(ctx, userKey, maxSessionsPerUser).Result()
	if err != nil {
		return nil, fmt.Errorf("list session ids by user: %w", err)
	}

	if len(sessionIDs) == 0 {
		return []*models.Session{}, nil
	}

	// Fetch all sessions using pipeline
	pipe := s.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(sessionIDs))
	for i, sidStr := range sessionIDs {
		cmds[i] = pipe.Get(ctx, sessionKeyPrefix+sidStr)
	}
	_, err = pipe.Exec(ctx)
	// Ignore errors here since some sessions may have expired
	// We'll filter those out below

	sessions := make([]*models.Session, 0, len(sessionIDs))
	expiredIDs := make([]string, 0)

	for i, cmd := range cmds {
		if _, err := cmd.Result(); errors.Is(err, redis.Nil) {
			// Session expired/deleted, mark for cleanup from user set
			expiredIDs = append(expiredIDs, sessionIDs[i])
			continue
		}
		if session := deserializeSessionCmd(cmd); session != nil {
			sessions = append(sessions, session)
		}
	}

	// Cleanup expired session IDs from user set (async, best effort)
	if len(expiredIDs) > 0 {
		go func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.client.SRem(cleanupCtx, userKey, expiredIDs)
		}()
	}

	return sessions, nil
}

func (s *RedisStore) UpdateSession(ctx context.Context, session *models.Session) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}

	key := s.sessionKey(session.ID)

	// Check if session exists
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("check session exists: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}

	data, err := json.Marshal(sessionToJSON(session))
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	ttl := getOrComputeTTL(ctx, s.client, key, session)
	err = s.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	return nil
}

func (s *RedisStore) DeleteSessionsByUser(ctx context.Context, userID id.UserID) error {
	userKey := s.userSessionsKey(userID)

	// Get all session IDs for this user
	sessionIDs, err := s.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return fmt.Errorf("list session ids for delete: %w", err)
	}

	if len(sessionIDs) == 0 {
		return fmt.Errorf("session not found: %w", sentinel.ErrNotFound)
	}

	// Delete all sessions and the user set
	pipe := s.client.Pipeline()
	for _, sidStr := range sessionIDs {
		pipe.Del(ctx, sessionKeyPrefix+sidStr)
	}
	pipe.Del(ctx, userKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete sessions by user: %w", err)
	}
	return nil
}

func (s *RedisStore) RevokeSessionIfActive(ctx context.Context, sessionID id.SessionID, now time.Time) error {
	_, err := s.Execute(ctx, sessionID,
		func(session *models.Session) error {
			if session.IsRevoked() {
				return ErrSessionRevoked
			}
			return nil
		},
		func(session *models.Session) {
			session.Revoke(now)
		},
	)
	return err
}

// DeleteExpiredSessions removes all sessions that have expired.
// Note: Redis automatically expires keys with TTL, so this is mostly a no-op.
// However, we do clean up stale entries from user session sets.
func (s *RedisStore) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	// Redis handles expiry automatically via TTL
	// This method exists for interface compatibility
	// In a production system, you might scan for orphaned user session sets
	return 0, nil
}

func (s *RedisStore) ListAll(ctx context.Context) (map[id.SessionID]*models.Session, error) {
	// Use SCAN to iterate over all session keys
	sessions := make(map[id.SessionID]*models.Session)
	var cursor uint64
	pattern := sessionKeyPrefix + "*"

	for {
		keys, nextCursor, err := s.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan sessions: %w", err)
		}

		if len(keys) > 0 {
			// Use pipeline to fetch all sessions
			pipe := s.client.Pipeline()
			cmds := make([]*redis.StringCmd, len(keys))
			for i, key := range keys {
				cmds[i] = pipe.Get(ctx, key)
			}
			_, err = pipe.Exec(ctx)
			if err != nil && !errors.Is(err, redis.Nil) {
				return nil, fmt.Errorf("get sessions: %w", err)
			}

			for _, cmd := range cmds {
				if session := deserializeSessionCmd(cmd); session != nil {
					sessions[session.ID] = session
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

// Execute atomically validates and mutates a session under optimistic lock.
func (s *RedisStore) Execute(ctx context.Context, sessionID id.SessionID, validate func(*models.Session) error, mutate func(*models.Session)) (*models.Session, error) {
	key := s.sessionKey(sessionID)
	var result *models.Session

	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return sentinel.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get session for execute: %w", err)
		}

		var j sessionJSON
		if err := json.Unmarshal([]byte(data), &j); err != nil {
			return fmt.Errorf("unmarshal session: %w", err)
		}

		session, err := sessionFromJSON(&j)
		if err != nil {
			return err
		}

		if err := validate(session); err != nil {
			return err // Domain error from callback - passed through unchanged
		}

		mutate(session)

		newData, err := json.Marshal(sessionToJSON(session))
		if err != nil {
			return fmt.Errorf("marshal session: %w", err)
		}

		ttl := getOrComputeTTL(ctx, tx, key, session)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, newData, ttl)
			return nil
		})
		if err != nil {
			return err
		}

		result = session
		return nil
	}, key)

	if err != nil {
		return nil, err
	}
	return result, nil
}
