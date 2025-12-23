package service

import (
	"context"
	"log/slog"

	"credo/internal/auth/models"
	device "credo/pkg/platform/middleware/device"
)

type deviceBindingState int

const (
	deviceStateOK       deviceBindingState = iota // session and cookie match (or both empty)
	deviceStateAttached                           // new device ID attached to session
	deviceStateMissing                            // session has device ID but cookie is missing
	deviceStateMismatch                           // session and cookie device IDs differ
)

func (s *Service) applyDeviceBinding(ctx context.Context, session *models.Session) {
	// Phase 1: soft launch — log signals, do not enforce.
	if !s.DeviceBindingEnabled {
		return
	}

	s.applyDeviceID(ctx, session)
	s.applyFingerprint(ctx, session)
}

// applyDeviceID handles device ID binding between session and cookie.
func (s *Service) applyDeviceID(ctx context.Context, session *models.Session) {
	cookieDeviceID := device.GetDeviceID(ctx)
	state := classifyDeviceState(session.DeviceID, cookieDeviceID)

	switch state {
	case deviceStateAttached:
		session.DeviceID = cookieDeviceID
		s.logDeviceEvent(ctx, slog.LevelInfo, "device_id_attached", session)

	case deviceStateMissing:
		s.logDeviceEvent(ctx, slog.LevelWarn, "device_id_missing", session)

	case deviceStateMismatch:
		s.logDeviceEvent(ctx, slog.LevelWarn, "device_id_mismatch", session)
	}
}

func (s *Service) applyFingerprint(ctx context.Context, session *models.Session) {
	currentFingerprint := device.GetDeviceFingerprint(ctx)
	if currentFingerprint == "" {
		return
	}

	// First fingerprint attachment
	if session.DeviceFingerprintHash == "" {
		session.DeviceFingerprintHash = currentFingerprint
		return
	}

	// Check for drift
	_, driftDetected := s.deviceService.CompareFingerprints(session.DeviceFingerprintHash, currentFingerprint)
	if driftDetected {
		s.logDeviceEvent(ctx, slog.LevelInfo, "fingerprint_drift_detected", session)
		session.DeviceFingerprintHash = currentFingerprint
	}
}

func classifyDeviceState(sessionDeviceID, cookieDeviceID string) deviceBindingState {
	switch {
	case sessionDeviceID == "" && cookieDeviceID != "":
		return deviceStateAttached
	case sessionDeviceID != "" && cookieDeviceID == "":
		return deviceStateMissing
	case sessionDeviceID != "" && cookieDeviceID != "" && sessionDeviceID != cookieDeviceID:
		return deviceStateMismatch
	default:
		return deviceStateOK
	}
}

func (s *Service) logDeviceEvent(ctx context.Context, level slog.Level, event string, session *models.Session) {
	if s.logger == nil {
		return
	}
	s.logger.Log(ctx, level, event,
		"session_id", session.ID.String(),
		"user_id", session.UserID.String(),
	)
}
