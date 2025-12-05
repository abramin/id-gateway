package jwttoken

import (
	dErrors "id-gateway/pkg/domain-errors"
)

func ExtractSessionIDFromAuthHeader(authHeader string) (string, error) {
	//TODO: replace with with actual jwt parsing

	const bearerPrefix = "Bearer "
	if len(authHeader) <= len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", dErrors.New(dErrors.CodeUnauthorized, "invalid authorization header")
	}

	token := authHeader[len(bearerPrefix):]
	const accessTokenPrefix = "at_sess_"
	if len(token) <= len(accessTokenPrefix) || token[:len(accessTokenPrefix)] != accessTokenPrefix {
		return "", dErrors.New(dErrors.CodeUnauthorized, "invalid access token")
	}

	sessionID := token[len(accessTokenPrefix):]
	return sessionID, nil
}
