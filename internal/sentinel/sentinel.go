package sentinel

import "errors"

// Sentinel dependency errors. Dependencies should return these (optionally wrapped)
// so services can translate them into domain errors exactly once.
var (
	ErrNotFound     = errors.New("not found")
	ErrInvalidInput = errors.New("invalid input")
	ErrBadRequest   = errors.New("bad request")
	ErrExpired      = errors.New("expired")
	ErrAlreadyUsed  = errors.New("already used")
	ErrInvalidState = errors.New("invalid state")
	ErrUnavailable  = errors.New("unavailable")
)
