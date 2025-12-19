#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://localhost:8080"
ADMIN_TOKEN="demo-admin-token"
REDIRECT_URI="http://localhost:3000/callback"
USER_EMAIL="demo@example.com"

# Use timestamp to ensure unique names
TIMESTAMP=$(date +%s)
TENANT_NAME="Demo Tenant $TIMESTAMP"
CLIENT_NAME="Demo Client $TIMESTAMP"

echo "=== 1. Create Tenant ==="
TENANT_RESPONSE=$(curl -sS -X POST "$BASE_URL/admin/tenants" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$TENANT_NAME\"}")
echo "$TENANT_RESPONSE" | jq .

TENANT_ID=$(echo "$TENANT_RESPONSE" | jq -r '.tenant_id')
if [ "$TENANT_ID" = "null" ] || [ -z "$TENANT_ID" ]; then
  echo "ERROR: Failed to create tenant"
  exit 1
fi
echo "TENANT_ID=$TENANT_ID"

echo ""
echo "=== 2. Create Client ==="
CLIENT_RESPONSE=$(curl -sS -X POST "$BASE_URL/admin/clients" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"name\": \"$CLIENT_NAME\",
    \"redirect_uris\": [\"$REDIRECT_URI\"],
    \"allowed_grants\": [\"authorization_code\", \"refresh_token\"],
    \"allowed_scopes\": [\"openid\", \"profile\", \"email\"]
  }")
echo "$CLIENT_RESPONSE" | jq .

CLIENT_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.client_id')
if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create client"
  exit 1
fi
echo "CLIENT_ID=$CLIENT_ID"

echo ""
echo "=== 3. Start Authorization (get auth code) ==="
AUTH_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/authorize" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$USER_EMAIL\",
    \"client_id\": \"$CLIENT_ID\",
    \"redirect_uri\": \"$REDIRECT_URI\",
    \"scopes\": [\"openid\", \"profile\", \"email\"],
    \"state\": \"xyz123\"
  }")
echo "$AUTH_RESPONSE" | jq .

AUTH_CODE=$(echo "$AUTH_RESPONSE" | jq -r '.code')
if [ "$AUTH_CODE" = "null" ] || [ -z "$AUTH_CODE" ]; then
  echo "ERROR: Failed to get authorization code"
  exit 1
fi
echo "AUTH_CODE=$AUTH_CODE"

echo ""
echo "=== 4. Exchange Code for Tokens ==="
TOKEN_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"client_id\": \"$CLIENT_ID\",
    \"code\": \"$AUTH_CODE\",
    \"redirect_uri\": \"$REDIRECT_URI\"
  }")
echo "$TOKEN_RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.refresh_token')
if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Failed to get access token"
  exit 1
fi
echo "ACCESS_TOKEN obtained (${#ACCESS_TOKEN} chars)"

echo ""
echo "=== 5. Grant Consent (requires auth) ==="
curl -sS -X POST "$BASE_URL/auth/consent" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes":["login","registry_check"]}' | jq .

echo ""
echo "=== 6. Get User Info ==="
curl -sS -X GET "$BASE_URL/auth/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo ""
echo "=== 7. List Sessions ==="
curl -sS -X GET "$BASE_URL/auth/sessions" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo ""
echo "=== 8. List Consents ==="
curl -sS -X GET "$BASE_URL/auth/consent" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo ""
echo "=== 9. Refresh Token ==="
REFRESH_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/token" \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"refresh_token\",
    \"client_id\": \"$CLIENT_ID\",
    \"refresh_token\": \"$REFRESH_TOKEN\"
  }")
echo "$REFRESH_RESPONSE" | jq .

NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.access_token')
if [ "$NEW_ACCESS_TOKEN" = "null" ] || [ -z "$NEW_ACCESS_TOKEN" ]; then
  echo "WARNING: Failed to refresh token, using original"
  NEW_ACCESS_TOKEN=$ACCESS_TOKEN
fi

echo ""
echo "=== 10. Revoke Specific Consent ==="
curl -sS -X POST "$BASE_URL/auth/consent/revoke" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes":["registry_check"]}' | jq .

echo ""
echo "=== 11. Revoke All Consents ==="
curl -sS -X POST "$BASE_URL/auth/consent/revoke-all" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq .

echo ""
echo "=== 12. Revoke Token ==="
curl -sS -X POST "$BASE_URL/auth/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$NEW_ACCESS_TOKEN\", \"client_id\": \"$CLIENT_ID\"}" | jq .

echo ""
echo "=== All tests completed successfully ==="
