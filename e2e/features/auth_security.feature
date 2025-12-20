Feature: OAuth2 Security - Client and Tenant Validation
    As a security engineer
    I want to validate that unknown and invalid clients are rejected
    So that the authorization server only serves registered clients

  Background:
    Given the ID Gateway is running

    @security @client-validation
  Scenario: Unknown client_id rejected (RFC 6749 §4.1.2.1)
    When I request authorization with unknown client_id "unknown-client-xyz"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @security @client-validation
  Scenario: Empty client_id rejected
    When I request authorization with empty client_id
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    # ============================================================
    # SECURITY SIMULATIONS (Documentation of known attack vectors)
    # ============================================================

    @security @simulation
  Scenario: PKCE not yet implemented
    Given PKCE is a recommended security feature
    Then log "SIMULATION: Authorization code interception vulnerability exists"
    And log "MITIGATION: Implement PKCE (code_challenge/code_verifier)"
    And log "STATUS: Not yet implemented"

    @security @simulation
  Scenario: Redirect URI validation not enforced
    Given redirect URI validation prevents token theft
    Then log "SIMULATION: Redirect URI manipulation vulnerability"
    And log "MITIGATION: Implement strict redirect_uri allowlist per client"
    And log "STATUS: Not yet implemented"

    @security @simulation
  Scenario: State parameter is optional
    Given CSRF protection is important
    Then log "SIMULATION: CSRF vulnerability via missing state parameter"
    And log "MITIGATION: State parameter validation is client responsibility"
    And log "STATUS: Optional in current implementation"

    @security @simulation
  Scenario: Token leakage prevention via authorization code flow
    Given implicit flow leaks tokens in browser history
    Then log "SIMULATION: Token leakage prevention"
    And log "MITIGATION: Use authorization code flow (currently implemented)"
    And log "STATUS: Good - implicit flow not supported"

    @security @simulation
  Scenario: Authorization code reuse is prevented
    Given authorization codes should be single-use
    Then log "SIMULATION: Authorization code reuse attack"
    And log "MITIGATION: Codes marked as used after exchange"
    And log "STATUS: Implemented - covered in normal flow tests"

    @security @simulation
  Scenario: Public clients should use PKCE not secrets
    Given public clients cannot keep secrets
    Then log "SIMULATION: Client secret exposure in public client"
    And log "MITIGATION: Use PKCE for public clients (SPAs/mobile)"
    And log "STATUS: Client secrets not required (good for public clients)"
    And log "TODO: Enforce PKCE when implemented"

    # ============================================================
    # PRD-026A VALIDATION (Behaviors enforced, E2E blocked on admin APIs)
    # ============================================================

    @security @prd-026a @simulation
  Scenario: Scope validation enforcement (PRD-026A FR-7)
    Given scope enforcement is enabled
    Then log "PRD-026A FR-7: Requested scopes must be subset of client.AllowedScopes"
    And log "BEHAVIOR: Requests with disallowed scopes return bad_request"
    And log "E2E: Requires admin API to configure client AllowedScopes"

    @security @prd-026a @simulation
  Scenario: Tenant status validation (PRD-026A FR-4.5.3)
    Given tenant status enforcement is enabled
    Then log "PRD-026A FR-4.5.3: Inactive tenant returns access_denied"
    And log "BEHAVIOR: Authorization rejected when tenant.status != active"
    And log "E2E: Requires admin API to modify tenant status"

    @security @prd-026a @simulation
  Scenario: Grant type validation (PRD-026A FR-3)
    Given grant type enforcement is enabled
    Then log "PRD-026A FR-3: Grant must be in client.AllowedGrants"
    And log "BEHAVIOR: Token requests with disallowed grant types are rejected"
    And log "E2E: Requires admin API to configure client AllowedGrants"

    # ============================================================
    # Token Revocation Security (RFC 7009 Compliance)
    # ============================================================

    @security @revocation
  Scenario: Revocation with forged JWT signature returns 200 (RFC 7009)
    # RFC 7009 §2.2: The authorization server responds with HTTP 200 regardless
    # of whether the token was valid. This prevents token fishing attacks where
    # malicious actors probe to discover valid tokens.
    Given a JWT with invalid signature "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid_signature"
    When I revoke the forged token
    Then the response status should be 200
    # Per RFC 7009: idempotent, no error for invalid tokens
    And the response field "revoked" should equal "true"

    @security @revocation
  Scenario: Revocation with expired but valid-signature JWT succeeds
    # Tokens should be revocable even after expiry - the user may want to
    # explicitly invalidate a token that has already timed out.
    When I initiate authorization with email "expired-revoke@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And I save the tokens from the response

    When I wait for the access token to expire
    And I revoke the expired access token
    Then the response status should be 200
    And the response field "revoked" should equal "true"

    # ============================================================
    # Device Binding Security
    # ============================================================

    @security @device-binding
  Scenario: Device ID is assigned during authorization
    # Security invariant: Each session is bound to a device identifier
    # to enable device-based session management and security policies.
    When I initiate authorization with email "device-test@example.com" and scopes "openid"
    Then the response status should be 200
    And the response should contain "device_id"
    And the response field "device_id" should not be empty

    @security @device-binding
  Scenario: Device ID persists across token refresh
    # Security invariant: The device binding established during authorization
    # should persist through token refresh operations.
    When I initiate authorization with email "device-persist@example.com" and scopes "openid"
    Then the response status should be 200
    And the response should contain "device_id"
    And I save the device id from the response
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And I save the tokens from the response

    When I refresh tokens with the saved refresh token
    Then the response status should be 200

    When I list sessions with the saved access token
    Then the response status should be 200
    And the session should have the same device id
