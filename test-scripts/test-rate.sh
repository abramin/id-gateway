#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://localhost:8080"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKENGEN="$SCRIPT_DIR/../bin/tokengen"

# Check if tokengen exists
if [ ! -x "$TOKENGEN" ]; then
  echo "Building tokengen..."
  (cd "$SCRIPT_DIR/.." && go build -o bin/tokengen ./cmd/tokengen)
fi

# Get admin token from tokengen
ADMIN_TOKEN=$("$TOKENGEN" admin -json | jq -r '.token')

# Create a real session for protected endpoint testing
echo "=== Setting up test session ==="
TIMESTAMP=$(date +%s)

# Create tenant
TENANT_RESPONSE=$(curl -sS -X POST "$BASE_URL/admin/tenants" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"RateTest Tenant $TIMESTAMP\"}")
TENANT_ID=$(echo "$TENANT_RESPONSE" | jq -r '.tenant_id')

if [ "$TENANT_ID" = "null" ] || [ -z "$TENANT_ID" ]; then
  echo "ERROR: Failed to create tenant"
  echo "$TENANT_RESPONSE"
  exit 1
fi
echo "Created tenant: $TENANT_ID"

# Create client
CLIENT_RESPONSE=$(curl -sS -X POST "$BASE_URL/admin/clients" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"name\": \"RateTest Client $TIMESTAMP\",
    \"redirect_uris\": [\"http://localhost:3000/callback\"],
    \"allowed_grants\": [\"authorization_code\", \"refresh_token\"],
    \"allowed_scopes\": [\"openid\", \"profile\", \"email\"]
  }")
CLIENT_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.client_id')

if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create client"
  echo "$CLIENT_RESPONSE"
  exit 1
fi
echo "Created client: $CLIENT_ID"

# Get auth code
AUTH_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/authorize" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"ratetest-$TIMESTAMP@example.com\",
    \"client_id\": \"$CLIENT_ID\",
    \"redirect_uri\": \"http://localhost:3000/callback\",
    \"scopes\": [\"openid\", \"profile\"],
    \"state\": \"test\"
  }")
AUTH_CODE=$(echo "$AUTH_RESPONSE" | jq -r '.code')

if [ "$AUTH_CODE" = "null" ] || [ -z "$AUTH_CODE" ]; then
  echo "ERROR: Failed to get auth code"
  echo "$AUTH_RESPONSE"
  exit 1
fi

# Exchange for tokens
TOKEN_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"client_id\": \"$CLIENT_ID\",
    \"code\": \"$AUTH_CODE\",
    \"redirect_uri\": \"http://localhost:3000/callback\"
  }")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Failed to get access token"
  echo "$TOKEN_RESPONSE"
  exit 1
fi
echo "Got access token: ${ACCESS_TOKEN:0:50}..."
echo ""

CONSENT_BODY='{"purposes":["login"]}'
CLASS_HITS="${1:-20}"   # how many times to hit each endpoint (default 20, or pass as arg)

log_hit() { printf "%-10s | req=%-3s | status=%s\n" "$1" "$2" "$3"; }

echo "=== Testing Rate Limits (${CLASS_HITS} requests per class) ==="
echo ""

# Auth class: /auth/authorize (public endpoint, 10 req/min)
echo "--- Auth Class (ClassAuth: 10 req/min) ---"
for i in $(seq 1 $CLASS_HITS); do
  status=$(curl -w "%{http_code}" -o /tmp/rl-auth.out -sS \
    -X POST "$BASE_URL/auth/authorize" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"ratelimit-$i@example.com\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"http://localhost:3000/callback\",\"scopes\":[\"openid\"],\"state\":\"s\"}")
  log_hit "auth" "$i" "$status"
done
echo ""

# Read class: /auth/userinfo (protected endpoint, 100 req/min)
echo "--- Read Class (ClassRead: 100 req/min) ---"
for i in $(seq 1 $CLASS_HITS); do
  status=$(curl -w "%{http_code}" -o /tmp/rl-read.out -sS \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$BASE_URL/auth/userinfo")
  log_hit "read" "$i" "$status"
done
echo ""

# Sensitive class: /auth/consent (protected endpoint, 30 req/min)
echo "--- Sensitive Class (ClassSensitive: 30 req/min) ---"
for i in $(seq 1 $CLASS_HITS); do
  status=$(curl -w "%{http_code}" -o /tmp/rl-sensitive.out -sS \
    -X POST "$BASE_URL/auth/consent" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$CONSENT_BODY")
  log_hit "sensitive" "$i" "$status"
done
echo ""

# Write class: /admin/tenants (admin endpoint, 50 req/min)
echo "--- Write Class (ClassWrite: 50 req/min) ---"
for i in $(seq 1 $CLASS_HITS); do
  status=$(curl -w "%{http_code}" -o /tmp/rl-write.out -sS \
    -X POST "$BASE_URL/admin/tenants" \
    -H "X-Admin-Token: $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"Rate Test Tenant $RANDOM\"}")
  log_hit "write" "$i" "$status"
done
echo ""

echo "=== Rate Limit Test Complete ==="
