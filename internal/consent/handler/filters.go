package handler

import (
	"strings"

	"credo/internal/consent/models"
	dErrors "credo/pkg/domain-errors"
)

func parseRecordFilter(status, purpose string) (*models.RecordFilter, error) {
	status = strings.TrimSpace(status)
	purpose = strings.TrimSpace(purpose)

	filter := &models.RecordFilter{}

	if status != "" {
		parsedStatus, err := models.ParseStatus(status)
		if err != nil {
			return nil, dErrors.New(dErrors.CodeValidation, "invalid status filter")
		}
		filter.Status = &parsedStatus
	}

	if purpose != "" {
		parsedPurpose, err := models.ParsePurpose(purpose)
		if err != nil {
			return nil, dErrors.New(dErrors.CodeValidation, "invalid purpose filter")
		}
		filter.Purpose = &parsedPurpose
	}

	if filter.Status == nil && filter.Purpose == nil {
		return nil, nil
	}

	return filter, nil
}
