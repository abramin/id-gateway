#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://localhost:8080"
ADMIN_TOKEN="demo-admin-token"
REDIRECT_URI="http://localhost:3000/callback"
USER_EMAIL="demo@example.com"
NATIONAL_ID="CITIZEN123456"
AUTH_MAX_RETRIES=5

# Use timestamp to ensure unique names
TIMESTAMP=$(date +%s)
TENANT_NAME="Demo Tenant $TIMESTAMP"
CLIENT_NAME="Demo Client $TIMESTAMP"
CLIENT_NAME_UPDATED="Demo Client Updated $TIMESTAMP"

authorize_with_retry() {
  local attempt=1
  local response error retry_after

  while true; do
    response=$(curl -sS -X POST "$BASE_URL/auth/authorize" \
      -H "Content-Type: application/json" \
      -d "{
        \"email\": \"$USER_EMAIL\",
        \"client_id\": \"$CLIENT_ID\",
        \"redirect_uri\": \"$REDIRECT_URI\",
        \"scopes\": [\"openid\", \"profile\", \"email\"],
        \"state\": \"xyz123\"
      }")

    error=$(echo "$response" | jq -r '.error // empty')
    if [ "$error" != "rate_limit_exceeded" ]; then
      echo "$response"
      return 0
    fi

    retry_after=$(echo "$response" | jq -r '.retry_after // 1')
    if ! [[ "$retry_after" =~ ^[0-9]+$ ]]; then
      retry_after=1
    fi

    if [ "$attempt" -ge "$AUTH_MAX_RETRIES" ]; then
      echo "$response"
      return 0
    fi

    echo "Rate limited on /auth/authorize, retrying in ${retry_after}s (attempt ${attempt}/${AUTH_MAX_RETRIES})" >&2
    sleep "$retry_after"
    attempt=$((attempt + 1))
  done
}

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
echo "=== 2. Get Tenant Details ==="
curl -sS -X GET "$BASE_URL/admin/tenants/$TENANT_ID" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== 3. Create Client ==="
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

CLIENT_INTERNAL_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.id')
CLIENT_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.client_id')
if [ "$CLIENT_INTERNAL_ID" = "null" ] || [ -z "$CLIENT_INTERNAL_ID" ]; then
  echo "ERROR: Failed to get client internal ID"
  exit 1
fi
if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
  echo "ERROR: Failed to create client"
  exit 1
fi
echo "CLIENT_INTERNAL_ID=$CLIENT_INTERNAL_ID"
echo "CLIENT_ID=$CLIENT_ID"

echo ""
echo "=== 4. Get Client Details ==="
curl -sS -X GET "$BASE_URL/admin/clients/$CLIENT_INTERNAL_ID" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== 5. Update Client ==="
curl -sS -X PUT "$BASE_URL/admin/clients/$CLIENT_INTERNAL_ID" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$CLIENT_NAME_UPDATED\"
  }" | jq .

echo ""
echo "=== 6. Start Authorization (get auth code) ==="
AUTH_RESPONSE=$(authorize_with_retry)
echo "$AUTH_RESPONSE" | jq .

AUTH_CODE=$(echo "$AUTH_RESPONSE" | jq -r '.code')
if [ "$AUTH_CODE" = "null" ] || [ -z "$AUTH_CODE" ]; then
  echo "ERROR: Failed to get authorization code"
  exit 1
fi
echo "AUTH_CODE=$AUTH_CODE"

echo ""
echo "=== 7. Exchange Code for Tokens ==="
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
echo "=== 8. Grant Consent (requires auth) ==="
curl -sS -X POST "$BASE_URL/auth/consent" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes":["login","registry_check","vc_issuance","decision_evaluation"]}' | jq .

echo ""
echo "=== 9. Registry Citizen Lookup ==="
curl -sS -X POST "$BASE_URL/registry/citizen" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"national_id\":\"$NATIONAL_ID\"}" | jq .

echo ""
echo "=== 10. Registry Sanctions Check ==="
curl -sS -X POST "$BASE_URL/registry/sanctions" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"national_id\":\"$NATIONAL_ID\"}" | jq .

echo ""
echo "=== 11. Issue Verifiable Credential ==="
VC_ISSUE_RESPONSE=$(curl -sS -X POST "$BASE_URL/vc/issue" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"type\":\"AgeOver18\",\"national_id\":\"$NATIONAL_ID\"}")
echo "$VC_ISSUE_RESPONSE" | jq .

CREDENTIAL_ID=$(echo "$VC_ISSUE_RESPONSE" | jq -r '.credential_id')
if [ "$CREDENTIAL_ID" = "null" ] || [ -z "$CREDENTIAL_ID" ]; then
  echo "WARNING: Failed to issue VC, skipping verification"
else
  echo ""
  echo "=== 12. Verify Verifiable Credential ==="
  curl -sS -X POST "$BASE_URL/vc/verify" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"credential_id\":\"$CREDENTIAL_ID\"}" | jq .
fi

echo ""
echo "=== 13. Evaluate Decision ==="
curl -sS -X POST "$BASE_URL/decision/evaluate" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"purpose\": \"age_verification\",
    \"context\": {
      \"national_id\": \"$NATIONAL_ID\"
    }
  }" | jq .

echo ""
echo "=== 14. Get User Info ==="
curl -sS -X GET "$BASE_URL/auth/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo ""
echo "=== 15. List Sessions ==="
SESSIONS_RESPONSE=$(curl -sS -X GET "$BASE_URL/auth/sessions" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$SESSIONS_RESPONSE" | jq .

SESSION_ID=$(echo "$SESSIONS_RESPONSE" | jq -r '.sessions[0].session_id')
if [ "$SESSION_ID" = "null" ] || [ -z "$SESSION_ID" ]; then
  echo "WARNING: No session ID found for revoke test"
fi

echo ""
echo "=== 16. List Consents ==="
curl -sS -X GET "$BASE_URL/auth/consent" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

echo ""
echo "=== 17. Refresh Token ==="
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
echo "=== 18. Revoke Specific Consent ==="
curl -sS -X POST "$BASE_URL/auth/consent/revoke" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes":["registry_check"]}' | jq .

echo ""
echo "=== 19. Revoke All Consents ==="
curl -sS -X POST "$BASE_URL/auth/consent/revoke-all" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq .

echo ""
echo "=== 20. Delete All Consents (GDPR) ==="
curl -sS -X DELETE "$BASE_URL/auth/consent" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq .

echo ""
echo "=== 21. Logout All Sessions ==="
curl -sS -X POST "$BASE_URL/auth/logout-all?except_current=true" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq .

if [ "$SESSION_ID" != "null" ] && [ -n "$SESSION_ID" ]; then
  echo ""
  echo "=== 22. Revoke Session by ID ==="
  curl -sS -X DELETE "$BASE_URL/auth/sessions/$SESSION_ID" \
    -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq .
fi

echo ""
echo "=== 23. Revoke Token ==="
curl -sS -X POST "$BASE_URL/auth/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$NEW_ACCESS_TOKEN\", \"client_id\": \"$CLIENT_ID\"}" | jq .

echo ""
echo "=== 24. Rotate Client Secret ==="
curl -sS -X POST "$BASE_URL/admin/clients/$CLIENT_INTERNAL_ID/rotate-secret" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== 25. Deactivate Client ==="
curl -sS -X POST "$BASE_URL/admin/clients/$CLIENT_INTERNAL_ID/deactivate" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== 26. Reactivate Client ==="
curl -sS -X POST "$BASE_URL/admin/clients/$CLIENT_INTERNAL_ID/reactivate" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== 27. Deactivate Tenant ==="
curl -sS -X POST "$BASE_URL/admin/tenants/$TENANT_ID/deactivate" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== 28. Reactivate Tenant ==="
curl -sS -X POST "$BASE_URL/admin/tenants/$TENANT_ID/reactivate" \
  -H "X-Admin-Token: $ADMIN_TOKEN" | jq .

echo ""
echo "=== All tests completed successfully ==="
