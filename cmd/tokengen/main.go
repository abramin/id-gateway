// Package main provides a CLI tool for generating test tokens for the Credo API.
// These tokens use dev/demo signing keys and will NOT work in production.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	jwttoken "credo/internal/jwt_token"

	"github.com/google/uuid"
)

const (
	// Dev signing key - matches config.go when JWT_SIGNING_KEY is not set
	devSigningKey = "dev-secret-key-change-in-production"

	// Demo signing key - matches config.go when CRENE_ENV=demo
	demoSigningKey = "demo-signing-key-change-me-locally"

	// Default admin token for local/dev environments
	devAdminToken = "demo-admin-token"

	// Default values matching production config
	defaultIssuerBaseURL = "http://localhost:8080"
	defaultAudience      = "credo-client"
	defaultTokenTTL      = 15 * time.Minute
)

type tokenOutput struct {
	Token     string            `json:"token"`
	Type      string            `json:"type"`
	ExpiresIn string            `json:"expires_in"`
	Claims    map[string]any    `json:"claims,omitempty"`
	Usage     map[string]string `json:"usage"`
}

func main() {
	// Subcommands
	accessCmd := flag.NewFlagSet("access", flag.ExitOnError)
	idCmd := flag.NewFlagSet("id", flag.ExitOnError)
	adminCmd := flag.NewFlagSet("admin", flag.ExitOnError)

	// Access token flags
	accessUserID := accessCmd.String("user-id", "", "User ID (UUID). Generated if empty.")
	accessSessionID := accessCmd.String("session-id", "", "Session ID (UUID). Generated if empty.")
	accessClientID := accessCmd.String("client-id", "test-client", "OAuth2 client ID")
	accessTenantID := accessCmd.String("tenant-id", "", "Tenant ID (optional)")
	accessScopes := accessCmd.String("scopes", "openid,profile,email", "Comma-separated scopes")
	accessTTL := accessCmd.Duration("ttl", defaultTokenTTL, "Token time-to-live")
	accessDemo := accessCmd.Bool("demo", false, "Use demo signing key instead of dev key")
	accessJSON := accessCmd.Bool("json", false, "Output as JSON")

	// ID token flags
	idUserID := idCmd.String("user-id", "", "User ID (UUID). Generated if empty.")
	idSessionID := idCmd.String("session-id", "", "Session ID (UUID). Generated if empty.")
	idClientID := idCmd.String("client-id", "test-client", "OAuth2 client ID")
	idTenantID := idCmd.String("tenant-id", "", "Tenant ID (optional)")
	idTTL := idCmd.Duration("ttl", defaultTokenTTL, "Token time-to-live")
	idDemo := idCmd.Bool("demo", false, "Use demo signing key instead of dev key")
	idJSON := idCmd.Bool("json", false, "Output as JSON")

	// Admin token flags
	adminJSON := adminCmd.Bool("json", false, "Output as JSON")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "access":
		accessCmd.Parse(os.Args[2:])
		generateAccessToken(*accessUserID, *accessSessionID, *accessClientID, *accessTenantID, *accessScopes, *accessTTL, *accessDemo, *accessJSON)
	case "id":
		idCmd.Parse(os.Args[2:])
		generateIDToken(*idUserID, *idSessionID, *idClientID, *idTenantID, *idTTL, *idDemo, *idJSON)
	case "admin":
		adminCmd.Parse(os.Args[2:])
		showAdminToken(*adminJSON)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`tokengen - Generate test tokens for Credo API

WARNING: These tokens use dev/demo signing keys and will NOT work in production.
         Only use for local development and testing.

Usage:
  tokengen <command> [flags]

Commands:
  access    Generate an access token (JWT)
  id        Generate an ID token (OIDC)
  admin     Show the admin API token

Examples:
  # Generate access token with defaults
  tokengen access

  # Generate access token with custom user
  tokengen access -user-id "550e8400-e29b-41d4-a716-446655440000"

  # Generate access token for specific tenant with custom TTL
  tokengen access -tenant-id "my-tenant" -ttl 1h

  # Generate token using demo signing key (for CRENE_ENV=demo)
  tokengen access -demo

  # Get admin token for X-Admin-Token header
  tokengen admin

  # Output as JSON
  tokengen access -json

Use "tokengen <command> -h" for more information about a command.`)
}

func generateAccessToken(userID, sessionID, clientID, tenantID, scopes string, ttl time.Duration, demo, jsonOutput bool) {
	signingKey := devSigningKey
	keyType := "dev"
	if demo {
		signingKey = demoSigningKey
		keyType = "demo"
	}

	uid := parseOrGenerateUUID(userID, "user-id")
	sid := parseOrGenerateUUID(sessionID, "session-id")
	scopeList := parseScopes(scopes)

	svc := jwttoken.NewJWTService(signingKey, defaultIssuerBaseURL, defaultAudience, ttl)

	token, jti, err := svc.GenerateAccessTokenWithJTI(uid, sid, clientID, tenantID, scopeList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		output := tokenOutput{
			Token:     token,
			Type:      "access_token",
			ExpiresIn: ttl.String(),
			Claims: map[string]any{
				"user_id":    uid.String(),
				"session_id": sid.String(),
				"client_id":  clientID,
				"tenant_id":  tenantID,
				"scope":      scopeList,
				"jti":        jti,
			},
			Usage: map[string]string{
				"header":      "Authorization: Bearer <token>",
				"signing_key": keyType,
			},
		}
		printJSON(output)
	} else {
		fmt.Println("Access Token (JWT)")
		fmt.Println("==================")
		fmt.Printf("Signing Key: %s\n", keyType)
		fmt.Printf("Expires In:  %s\n", ttl)
		fmt.Printf("User ID:     %s\n", uid)
		fmt.Printf("Session ID:  %s\n", sid)
		fmt.Printf("Client ID:   %s\n", clientID)
		if tenantID != "" {
			fmt.Printf("Tenant ID:   %s\n", tenantID)
		}
		fmt.Printf("Scopes:      %v\n", scopeList)
		fmt.Printf("JTI:         %s\n", jti)
		fmt.Println()
		fmt.Println("Token:")
		fmt.Println(token)
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  curl -H \"Authorization: Bearer <token>\" http://localhost:8080/...")
	}
}

func generateIDToken(userID, sessionID, clientID, tenantID string, ttl time.Duration, demo, jsonOutput bool) {
	signingKey := devSigningKey
	keyType := "dev"
	if demo {
		signingKey = demoSigningKey
		keyType = "demo"
	}

	uid := parseOrGenerateUUID(userID, "user-id")
	sid := parseOrGenerateUUID(sessionID, "session-id")

	svc := jwttoken.NewJWTService(signingKey, defaultIssuerBaseURL, defaultAudience, ttl)

	token, err := svc.GenerateIDToken(uid, sid, clientID, tenantID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		output := tokenOutput{
			Token:     token,
			Type:      "id_token",
			ExpiresIn: ttl.String(),
			Claims: map[string]any{
				"sub":       uid.String(),
				"sid":       sid.String(),
				"azp":       clientID,
				"tenant_id": tenantID,
			},
			Usage: map[string]string{
				"signing_key": keyType,
			},
		}
		printJSON(output)
	} else {
		fmt.Println("ID Token (OIDC)")
		fmt.Println("===============")
		fmt.Printf("Signing Key: %s\n", keyType)
		fmt.Printf("Expires In:  %s\n", ttl)
		fmt.Printf("Subject:     %s\n", uid)
		fmt.Printf("Session ID:  %s\n", sid)
		fmt.Printf("Client ID:   %s\n", clientID)
		if tenantID != "" {
			fmt.Printf("Tenant ID:   %s\n", tenantID)
		}
		fmt.Println()
		fmt.Println("Token:")
		fmt.Println(token)
	}
}

func showAdminToken(jsonOutput bool) {
	if jsonOutput {
		output := tokenOutput{
			Token: devAdminToken,
			Type:  "admin_token",
			Usage: map[string]string{
				"header": "X-Admin-Token: " + devAdminToken,
				"note":   "Works when CRENE_ENV is local/dev/development/testing/test",
			},
		}
		printJSON(output)
	} else {
		fmt.Println("Admin API Token")
		fmt.Println("===============")
		fmt.Printf("Token: %s\n", devAdminToken)
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  curl -H \"X-Admin-Token: " + devAdminToken + "\" http://localhost:8080/...")
		fmt.Println()
		fmt.Println("Note: This token works when CRENE_ENV is local/dev/development/testing/test")
	}
}

func parseOrGenerateUUID(input, fieldName string) uuid.UUID {
	if input == "" {
		return uuid.New()
	}
	parsed, err := uuid.Parse(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid %s UUID: %s\n", fieldName, input)
		os.Exit(1)
	}
	return parsed
}

func parseScopes(scopes string) []string {
	if scopes == "" {
		return []string{}
	}
	parts := strings.Split(scopes, ",")
	result := make([]string, 0, len(parts))
	for _, s := range parts {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
