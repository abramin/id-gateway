Feature: OAuth2 Authorization Code Flow - Normal Path

  Background:
    * url baseUrl
    * def oauth = karate.get('oauth')
    * def testUser = karate.get('testUser')

  Scenario: Complete OAuth2 authorization code flow (POST /auth/authorize)
    # Step 1: Initiate authorization request with email
    # POST /auth/authorize creates a user (if not exists) and session
    * def state = java.util.UUID.randomUUID().toString()

    Given path '/auth/authorize'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "email": "#(testUser.username)",
        "client_id": "#(oauth.clientId)",
        "scopes": ["openid", "profile"],
        "redirect_uri": "#(oauth.redirectUri)",
        "state": "#(state)"
      }
      """
    When method POST
    Then status 200
    And match response.code == '#string'
    And match response.redirect_uri == '#string'

    # The redirect_uri should contain the code and state
    * def redirectUri = response.redirect_uri
    * assert redirectUri.contains('code=')
    * assert redirectUri.contains('state=' + state)

    # Extract authorization code from redirect URL
    * def authCode = response.code
    * karate.log('Authorization code:', authCode)

    # Step 2: Exchange authorization code for tokens
    Given path '/auth/token'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "grant_type": "authorization_code",
        "code": "#(authCode)",
        "redirect_uri": "#(oauth.redirectUri)",
        "client_id": "#(oauth.clientId)"
      }
      """
    When method POST
    Then status 200
    And match response.access_token == '#string'
    And match response.id_token == '#string'
    And match response.expires_in == '#number'

    # Save tokens for next step
    * def accessToken = response.access_token
    * def idToken = response.id_token

    # Step 3: Verify ID token structure (JWT)
    * def idTokenPayload = karate.call('classpath:helpers/jwt-decoder.js', idToken)
    * match idTokenPayload.sub == '#string'
    * match idTokenPayload.exp == '#number'
    * match idTokenPayload.iat == '#number'

    # Step 4: Use access token to get user info
    Given path '/auth/userinfo'
    And header Authorization = 'Bearer ' + accessToken
    When method GET
    Then status 200
    And match response.sub == '#string'
    And match response.email == testUser.username
    And match response.email_verified == '#boolean'
    And match response.given_name == '#present'
    And match response.family_name == '#present'

  Scenario: Authorization request validation - missing required fields
    Given path '/auth/authorize'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "email": "test@example.com"
      }
      """
    When method POST
    Then status 400
    And match response.error == 'bad_request'

  Scenario: Authorization request validation - invalid email
    Given path '/auth/authorize'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "email": "not-an-email",
        "client_id": "test-client",
        "scopes": ["openid"],
        "redirect_uri": "http://localhost:3000/callback"
      }
      """
    When method POST
    Then status 400
    And match response.error == 'bad_request'

  Scenario: Authorization request validation - empty scopes
    Given path '/auth/authorize'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "email": "test@example.com",
        "client_id": "test-client",
        "scopes": [],
        "redirect_uri": "http://localhost:3000/callback"
      }
      """
    When method POST
    Then status 400
    And match response.error == 'bad_request'

  Scenario: Token exchange validation - invalid authorization code
    Given path '/auth/token'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "grant_type": "authorization_code",
        "code": "invalid-code-12345",
        "redirect_uri": "http://localhost:3000/callback",
        "client_id": "test-client"
      }
      """
    When method POST
    Then status 401
    And match response.error == 'unauthorized'

  Scenario: Token exchange validation - invalid grant type
    Given path '/auth/token'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "grant_type": "password",
        "code": "some-code",
        "redirect_uri": "http://localhost:3000/callback",
        "client_id": "test-client"
      }
      """
    When method POST
    Then status 400
    And match response.error == 'bad_request'

  Scenario: Token exchange validation - authorization code reuse (code already used)
    # First, create a session and exchange the code
    Given path '/auth/authorize'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "email": "reuse-test@example.com",
        "client_id": "test-client",
        "scopes": ["openid"],
        "redirect_uri": "http://localhost:3000/callback",
        "state": "test-state"
      }
      """
    When method POST
    Then status 200
    * def authCode = response.code

    # Exchange code for token (first time - should succeed)
    Given path '/auth/token'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "grant_type": "authorization_code",
        "code": "#(authCode)",
        "redirect_uri": "http://localhost:3000/callback",
        "client_id": "test-client"
      }
      """
    When method POST
    Then status 200

    # Attempt to reuse the same code (should fail)
    Given path '/auth/token'
    And header Content-Type = 'application/json'
    And request
      """
      {
        "grant_type": "authorization_code",
        "code": "#(authCode)",
        "redirect_uri": "http://localhost:3000/callback",
        "client_id": "test-client"
      }
      """
    When method POST
    Then status 401
    And match response.error == 'unauthorized'

  Scenario: UserInfo endpoint - missing authorization header
    Given path '/auth/userinfo'
    When method GET
    Then status 401
    And match response.error == 'unauthorized'

  Scenario: UserInfo endpoint - invalid bearer token
    Given path '/auth/userinfo'
    And header Authorization = 'Bearer invalid-token-xyz'
    When method GET
    Then status 401
    And match response.error == 'unauthorized'
