Feature: OAuth2 Authorization Code Flow - Normal Path

  Background:
    Given the API base URL is configured
    And OAuth2 client credentials are available
    And test user credentials are available

    @normal @oauth2
  Scenario: Complete OAuth2 authorization code flow
    # Step 1: Initiate authorization request with email
    Given I generate a random state value
    When I POST to "/auth/authorize" with:
      | email        | test@example.com              |
      | client_id    | test-client                   |
      | scopes       | openid,profile                |
      | redirect_uri | http://localhost:3000/callback|
      | state        | <state>                       |
    Then the response status should be 200
    And the response should contain "code"
    And the response should contain "redirect_uri"
    And the redirect URI should contain the state parameter
    And I save the authorization code

    # Step 2: Exchange authorization code for tokens
    When I POST to "/auth/token" with:
      | grant_type   | authorization_code            |
      | code         | <authorization_code>          |
      | redirect_uri | http://localhost:3000/callback|
      | client_id    | test-client                   |
    Then the response status should be 200
    And the response should contain "access_token"
    And the response should contain "id_token"
    And the response should contain "expires_in"
    And I save the access token and id token

    # Step 3: Verify ID token structure (JWT)
    Then the ID token should be a valid JWT
    And the ID token should contain "sub"
    And the ID token should contain "exp"
    And the ID token should contain "iat"

    # Step 4: Use access token to get user info
    When I GET "/auth/userinfo" with bearer token
    Then the response status should be 200
    And the response should contain "sub"
    And the response should contain "email"
    And the response field "email" should equal "test@example.com"

    @normal @validation
  Scenario: Authorization request validation - missing required fields
    When I POST to "/auth/authorize" with:
      | email | test@example.com |
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Authorization request validation - invalid email
    When I POST to "/auth/authorize" with:
      | email        | not-an-email                  |
      | client_id    | test-client                   |
      | scopes       | openid                        |
      | redirect_uri | http://localhost:3000/callback|
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Authorization request validation - empty scopes
    When I POST to "/auth/authorize" with:
      | email        | test@example.com              |
      | client_id    | test-client                   |
      | scopes       |                               |
      | redirect_uri | http://localhost:3000/callback|
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Token exchange validation - invalid authorization code
    When I POST to "/auth/token" with:
      | grant_type   | authorization_code            |
      | code         | invalid-code-12345            |
      | redirect_uri | http://localhost:3000/callback|
      | client_id    | test-client                   |
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @normal @validation
  Scenario: Token exchange validation - invalid grant type
    When I POST to "/auth/token" with:
      | grant_type   | password                      |
      | code         | some-code                     |
      | redirect_uri | http://localhost:3000/callback|
      | client_id    | test-client                   |
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @normal @validation
  Scenario: Token exchange validation - authorization code reuse
    # First, create a session and get authorization code
    When I POST to "/auth/authorize" with:
      | email        | reuse-test@example.com        |
      | client_id    | test-client                   |
      | scopes       | openid                        |
      | redirect_uri | http://localhost:3000/callback|
      | state        | test-state                    |
    Then the response status should be 200
    And I save the authorization code

    # Exchange code for token (first time - should succeed)
    When I POST to "/auth/token" with:
      | grant_type   | authorization_code            |
      | code         | <authorization_code>          |
      | redirect_uri | http://localhost:3000/callback|
      | client_id    | test-client                   |
    Then the response status should be 200

    # Attempt to reuse the same code (should fail)
    When I POST to "/auth/token" with:
      | grant_type   | authorization_code            |
      | code         | <authorization_code>          |
      | redirect_uri | http://localhost:3000/callback|
      | client_id    | test-client                   |
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @normal @validation
  Scenario: UserInfo endpoint - missing authorization header
    When I GET "/auth/userinfo" without authorization
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @normal @validation
  Scenario: UserInfo endpoint - invalid bearer token
    When I GET "/auth/userinfo" with invalid bearer token "invalid-token-xyz"
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"
