Feature: Token lifecycle and session management (PRD-016)
    As a user
    I want secure token refresh and revocation
    So that sessions can be rotated or revoked per PRD-016

  Background:
    Given the ID Gateway is running

    @token @refresh
  Scenario: Refresh token rotation rejects reuse (RFC 6749 §5.2)
    When I initiate authorization with email "rotate@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And the response should contain "refresh_token"
    And I save the tokens from the response

    When I refresh tokens with the saved refresh token
    Then the response status should be 200
    And the response should contain "refresh_token"
    And the new refresh token should differ from the previous one

    When I attempt to refresh with the previous refresh token
    # RFC 6749 §5.2: reused refresh token returns 400 with invalid_grant
    Then the response status should be 400
    And the response field "error" should equal "invalid_grant"

    @token @revocation
  Scenario: Refresh token revocation blocks future refresh (RFC 6749 §5.2)
    When I initiate authorization with email "revoke-refresh@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And I save the tokens from the response

    When I revoke the saved refresh token
    Then the response status should be 200
    And the response field "revoked" should equal "true"

    When I refresh tokens with the saved refresh token
    # RFC 6749 §5.2: revoked refresh token returns 400 with invalid_grant
    Then the response status should be 400
    And the response field "error" should equal "invalid_grant"

    @token @revocation
  Scenario: Access token revocation invalidates the session
    When I initiate authorization with email "revoke-access@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And I save the tokens from the response

    When I revoke the saved access token
    Then the response status should be 200

    When I attempt to get user info with the saved access token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @token @sessions
  Scenario: Revoke a specific session from another active session
    When I initiate authorization with email "session-mgmt@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And I save the tokens from the response as "primary"

    When I initiate authorization with email "session-mgmt@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And I save the tokens from the response as "secondary"

    When I list sessions with access token "secondary"
    Then the response status should be 200
    And the response should list at least 2 sessions
    And I save the current session id as "secondary"

    When I revoke session "secondary" using access token "primary"
    Then the response status should be 200
    And the response field "revoked" should equal "true"

    When I request user info with access token "secondary"
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    # ============================================================
    # PRD-026A FR-4.5.4: Client/User Status Validation on Refresh
    # NOTE: These scenarios document expected behavior. Full E2E testing
    # requires admin APIs to modify client/user status. Unit tests in
    # service/token_refresh_test.go provide coverage for these cases.
    # ============================================================

    @token @refresh @prd-026a @simulation
  Scenario: Refresh token rejected when client is inactive (PRD-026A FR-4.5.4)
    # This scenario documents the expected behavior:
    # 1. User completes OAuth2 authorization
    # 2. Client is marked as inactive (via admin API - not yet available in E2E)
    # 3. Refresh attempt returns 403 Forbidden
    Given client status validation is enforced on token refresh
    Then log "PRD-026A FR-4.5.4: Inactive client MUST be rejected on refresh"
    And log "COVERAGE: Unit tested in service/token_refresh_test.go (client inactive - PRD-026A FR-4.5.4)"
    And log "E2E: Requires admin API to modify client status"

    @token @refresh @prd-026a @simulation
  Scenario: Refresh token rejected when user is inactive (PRD-026A FR-4.5.4)
    # This scenario documents the expected behavior:
    # 1. User completes OAuth2 authorization
    # 2. User account is marked as inactive (via admin API - not yet available in E2E)
    # 3. Refresh attempt returns 403 Forbidden
    Given user status validation is enforced on token refresh
    Then log "PRD-026A FR-4.5.4: Inactive user MUST be rejected on refresh"
    And log "COVERAGE: Unit tested in service/token_refresh_test.go (user inactive - PRD-026A FR-4.5.4)"
    And log "E2E: Requires admin API to modify user status"
