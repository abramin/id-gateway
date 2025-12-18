Feature: Rate Limiting & Abuse Prevention
    As a system operator
    I want to rate limit requests per IP and user
    So that brute force attacks and abuse are prevented

  # Per PRD-017: Rate Limiting & Abuse Prevention

  Background:
    Given the ID Gateway is running

  # ============================================================
  # FR-1: Per-IP Rate Limiting
  # ============================================================

  @ratelimit @ip @prd-017
  Scenario: IP rate limit headers present in response
    When I make a request to "/auth/userinfo" with valid token
    Then the response should contain header "X-RateLimit-Limit"
    And the response should contain header "X-RateLimit-Remaining"
    And the response should contain header "X-RateLimit-Reset"

  @ratelimit @ip @prd-017
  Scenario: IP rate limit enforced on auth endpoint (10 req/min)
    Given I am making requests from IP "192.168.1.50"
    When I make 10 requests to "/auth/authorize" within 1 minute
    Then all 10 requests should succeed with status 200
    When I make the 11th request to "/auth/authorize"
    Then the response status should be 429
    And the response field "error" should equal "rate_limit_exceeded"
    And the response should contain header "Retry-After"

  @ratelimit @ip @prd-017
  Scenario: IP rate limit enforced on sensitive endpoints (30 req/min)
    Given I am making requests from IP "192.168.1.51"
    When I make 30 requests to "/consent" within 1 minute
    Then all 30 requests should succeed
    When I make the 31st request to "/consent"
    Then the response status should be 429

  @ratelimit @ip @prd-017
  Scenario: IP rate limit enforced on read endpoints (100 req/min)
    Given I am making requests from IP "192.168.1.52"
    When I make 100 requests to "/auth/userinfo" within 1 minute
    Then all 100 requests should succeed
    When I make the 101st request to "/auth/userinfo"
    Then the response status should be 429

  @ratelimit @ip @prd-017
  Scenario: Rate limit resets after window expires
    Given I am making requests from IP "192.168.1.53"
    And I have exhausted the rate limit on "/auth/authorize"
    When I wait for the rate limit window to expire
    And I make a request to "/auth/authorize"
    Then the response status should be 200

  # ============================================================
  # FR-2: Per-User Rate Limiting
  # ============================================================

  @ratelimit @user @prd-017
  Scenario: User rate limit enforced on consent operations (50 req/hour)
    Given I am authenticated as user "test-user-1"
    When I make 50 consent requests within 1 hour
    Then all 50 requests should succeed
    When I make the 51st consent request
    Then the response status should be 429
    And the response field "error" should equal "user_rate_limit_exceeded"
    And the response field "quota_limit" should equal 50
    And the response field "quota_remaining" should equal 0

  @ratelimit @user @prd-017
  Scenario: User rate limit for VC issuance (20 req/hour)
    Given I am authenticated as user "test-user-2"
    When I make 20 VC issuance requests within 1 hour
    Then all 20 requests should succeed
    When I make the 21st VC issuance request
    Then the response status should be 429

  @ratelimit @user @prd-017
  Scenario: Both IP and user limits must pass
    Given I am authenticated as user "test-user-3"
    And I am making requests from IP "192.168.1.60"
    When the IP limit is not exceeded
    And the user limit is exceeded
    Then the request should be rejected with 429

  # ============================================================
  # FR-2b: Authentication-Specific Protections (OWASP)
  # ============================================================

  @ratelimit @auth @owasp @prd-017
  Scenario: Auth lockout after failed attempts (5 attempts/15 min)
    Given I am attempting login for user "locked-user@example.com" from IP "192.168.1.70"
    When I fail authentication 5 times within 15 minutes
    Then the 6th attempt should return 429
    And the response should indicate lockout

  @ratelimit @auth @owasp @prd-017
  Scenario: Hard lockout after 10 daily failures
    Given I am attempting login for user "hardlock@example.com" from IP "192.168.1.71"
    When I fail authentication 10 times within 24 hours
    Then the account should be hard locked for 15 minutes
    And the audit event "auth.lockout" should be emitted

  @ratelimit @auth @owasp @prd-017
  Scenario: Progressive backoff on auth failures
    Given I am attempting login for user "backoff@example.com" from IP "192.168.1.72"
    When I fail authentication once
    Then the next response should be delayed by at least 250ms
    When I fail authentication again
    Then the next response should be delayed by at least 500ms

  @ratelimit @auth @owasp @prd-017
  Scenario: Generic error messages prevent enumeration
    When I attempt login with invalid username "nonexistent@example.com"
    Then the response error message should be generic
    When I attempt login with valid username but invalid password
    Then the response error message should be the same generic message

  @ratelimit @auth @owasp @prd-017
  Scenario: CAPTCHA required after consecutive lockouts
    Given user "captcha@example.com" has been locked out 3 times in 24 hours
    When I attempt to login as "captcha@example.com"
    Then the response should indicate CAPTCHA is required

  # ============================================================
  # FR-3: Sliding Window Algorithm
  # ============================================================

  @ratelimit @algorithm @prd-017
  Scenario: Sliding window prevents boundary attacks
    Given I am making requests from IP "192.168.1.80"
    And the rate limit is 10 requests per minute
    When I make 10 requests at second 59 of minute 1
    And I make 5 requests at second 1 of minute 2
    Then only 5 of the second batch should succeed
    # Fixed window would allow all 15 (10 at end + 10 at start)

  # ============================================================
  # FR-4: Rate Limit Bypass (Allowlist)
  # ============================================================

  @ratelimit @allowlist @admin @prd-017
  Scenario: Admin can add IP to allowlist
    Given I am authenticated as admin
    When I add IP "10.0.0.100" to the rate limit allowlist with reason "Internal monitoring"
    Then the response should confirm allowlisting
    And the audit event "rate_limit_allowlist_added" should be emitted

  @ratelimit @allowlist @prd-017
  Scenario: Allowlisted IP bypasses rate limits
    Given IP "10.0.0.100" is on the allowlist
    When I make 200 requests from IP "10.0.0.100" to "/auth/authorize"
    Then all 200 requests should succeed
    And no rate limit headers should indicate limit exceeded

  @ratelimit @allowlist @prd-017
  Scenario: Allowlist entry with expiration
    Given I am authenticated as admin
    When I add IP "10.0.0.101" to allowlist with expiration in 1 hour
    Then the allowlist entry should have expires_at set
    When the allowlist entry expires
    Then requests from IP "10.0.0.101" should be rate limited normally

  @ratelimit @allowlist @admin @prd-017
  Scenario: Admin can remove from allowlist
    Given IP "10.0.0.100" is on the allowlist
    And I am authenticated as admin
    When I remove IP "10.0.0.100" from the allowlist
    Then the IP should no longer be allowlisted
    And requests from that IP should be rate limited

  # ============================================================
  # FR-5: Partner API Quotas (API Keys)
  # ============================================================

  @ratelimit @quota @partner @prd-017 @simulation
  Scenario: Free tier quota enforcement (1000 req/month)
    Given API key "partner-free-123" has tier "free"
    When the API key has made 1000 requests this month
    And I make another request with the API key
    Then the response status should be 429
    And the response should indicate quota exceeded

  @ratelimit @quota @partner @prd-017 @simulation
  Scenario: Starter tier with overage allowed
    Given API key "partner-starter-456" has tier "starter"
    When the API key has made 10000 requests this month
    And I make another request with the API key
    Then the request should succeed
    And overage should be recorded for billing

  @ratelimit @quota @partner @prd-017 @simulation
  Scenario: Quota headers present in response
    Given API key "partner-business-789" has tier "business"
    When I make a request with the API key
    Then the response should contain header "X-Quota-Limit"
    And the response should contain header "X-Quota-Remaining"
    And the response should contain header "X-Quota-Reset"

  # ============================================================
  # FR-6: DDoS Protection (Global Throttling)
  # ============================================================

  @ratelimit @ddos @prd-017 @simulation
  Scenario: Global throttle returns 503 when exceeded
    Given the global request rate exceeds 10000 req/sec
    When I make a request
    Then the response status should be 503
    And the response field "error" should equal "service_unavailable"
    And the response should contain header "Retry-After"

  # ============================================================
  # Audit Events
  # ============================================================

  @ratelimit @audit @prd-017
  Scenario: Rate limit violation emits audit event
    Given I am making requests from IP "192.168.1.90"
    When I exceed the rate limit on "/auth/authorize"
    Then the audit event "rate_limit_exceeded" should be emitted
    And the audit event should contain the IP address
    And the audit event should contain the endpoint class

  # ============================================================
  # Admin Reset Operations
  # ============================================================

  @ratelimit @admin @prd-017
  Scenario: Admin can reset rate limit for IP
    Given IP "192.168.1.95" has exceeded its rate limit
    And I am authenticated as admin
    When I reset the rate limit for IP "192.168.1.95"
    Then the next request from that IP should succeed
    And the audit event "rate_limit_reset" should be emitted

  # ============================================================
  # Configuration
  # ============================================================

  @ratelimit @config @prd-017 @simulation
  Scenario: Rate limits configurable via environment
    Given rate limits are configured via environment variables
    Then the auth endpoint limit should match RATELIMIT_AUTH_LIMIT
    And the read endpoint limit should match RATELIMIT_READ_LIMIT
