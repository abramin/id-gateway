package service

import (
	"context"

	"credo/internal/auth/models"
	"credo/internal/platform/middleware"
)

func (s *Service) applyDeviceBinding(ctx context.Context, session *models.Session) {
	// Phase 1: soft launch — log signals, do not enforce.
	if !s.DeviceBindingEnabled {
		return
	}

	cookieDeviceID := middleware.GetDeviceID(ctx)
	if session.DeviceID == "" && cookieDeviceID != "" {
		session.DeviceID = cookieDeviceID
		if s.logger != nil {
			s.logger.InfoContext(ctx, "device_id_attached",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
	}
	if session.DeviceID != "" && cookieDeviceID == "" {
		if s.logger != nil {
			s.logger.WarnContext(ctx, "device_id_missing",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
	} else if session.DeviceID != "" && cookieDeviceID != "" && session.DeviceID != cookieDeviceID {
		if s.logger != nil {
			s.logger.WarnContext(ctx, "device_id_mismatch",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
	}

	userAgent := middleware.GetUserAgent(ctx)
	currentFingerprint := s.deviceService.ComputeFingerprint(userAgent)
	_, driftDetected := s.deviceService.CompareFingerprints(session.DeviceFingerprintHash, currentFingerprint)
	if session.DeviceFingerprintHash == "" && currentFingerprint != "" {
		session.DeviceFingerprintHash = currentFingerprint
	} else if driftDetected {
		if s.logger != nil {
			s.logger.InfoContext(ctx, "fingerprint_drift_detected",
				"session_id", session.ID.String(),
				"user_id", session.UserID.String(),
			)
		}
		session.DeviceFingerprintHash = currentFingerprint
	}
}
