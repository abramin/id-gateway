Feature: OAuth2 Authorization Code Flow - Normal Path
    As a client application
    I want to authenticate users via OAuth2
    So that I can access protected resources

  Background:
    Given the ID Gateway is running

    @normal
  Scenario: Complete OAuth2 authorization code flow
    When I initiate authorization with email "test@example.com" and scopes "openid,profile"
    Then the response status should be 200
    And the response should contain an authorization code
    And the response field "redirect_uri" should contain "code="
    And the response field "redirect_uri" should contain "state="
    And I save the authorization code
    
    When I exchange the authorization code for tokens
    Then the response status should be 200
    And the response should contain "access_token"
    And the response should contain "id_token"
    And the response should contain "refresh_token"
    And the response should contain "expires_in"
    
    When I request user info with the access token
    Then the response status should be 200
    And the response should contain "email"
    And the response field "email" should equal "test@example.com"

    @normal @scope
  Scenario: Scope downgrade - requesting subset of allowed scopes succeeds
    # Client has allowed_scopes: ["openid", "profile", "email"]
    # Requesting just "openid" (a subset) should succeed
    When I initiate authorization with email "scope-downgrade@example.com" and scopes "openid"
    Then the response status should be 200
    And the response should contain an authorization code
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And the response should contain "access_token"

    @normal @scope
  Scenario: Default scope applied when scopes omitted
    When I initiate authorization with email "default-scope@example.com" without scopes
    Then the response status should be 200
    And the response should contain an authorization code
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And the response field "scope" should equal "openid"

    @normal @validation
  Scenario: Authorization request validation - missing required fields
    When I POST to "/auth/authorize" with empty body
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Authorization request validation - invalid email
    When I POST to "/auth/authorize" with invalid email "not-an-email"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Token exchange validation - invalid authorization code (RFC 6749 §5.2)
    When I exchange invalid authorization code "invalid-code-12345"
    # RFC 6749 §5.2: invalid authorization code returns 400 with invalid_grant
    Then the response status should be 400
    And the response field "error" should equal "invalid_grant"

    @normal @validation
  Scenario: Token exchange validation - invalid grant type
    When I POST to "/auth/token" with grant_type "password"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Authorization code reuse prevention (RFC 6749 §5.2)
    When I initiate authorization with email "reuse-test@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200

    When I attempt to reuse the same authorization code
    # RFC 6749 §5.2: reused authorization code returns 400 with invalid_grant
    Then the response status should be 400
    And the response field "error" should equal "invalid_grant"

    @normal @validation
  Scenario: UserInfo endpoint - missing authorization header
    When I GET "/auth/userinfo" without authorization
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @normal @validation
  Scenario: UserInfo endpoint - invalid bearer token
    When I GET "/auth/userinfo" with invalid token "invalid-token-xyz"
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"
