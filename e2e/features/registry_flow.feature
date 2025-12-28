Feature: Registry Integration - Citizen and Sanctions Lookup
    As an authenticated user with proper consent
    I want to lookup citizen records and check sanctions status
    So that identity verification and AML/CTF compliance can be performed

  Background:
    Given the ID Gateway is running
    And I am authenticated as "registry-test@example.com"
    And I have granted consent for purposes "registry_check"

    @registry @citizen @normal
  Scenario: Successful citizen registry lookup with full data
    When I lookup citizen record for national_id "CITIZEN123456"
    Then the response status should be 200
    And the response should contain "national_id"
    And the response should contain "full_name"
    And the response should contain "date_of_birth"
    And the response should contain "address"
    And the response should contain "valid"
    And the response should contain "source"
    And the response should contain "checked_at"
    And the response field "national_id" should equal "CITIZEN123456"
    And the response field "valid" should equal true
    And the response field "source" should not be empty

    @registry @citizen @normal
  Scenario: Citizen lookup returns different data for different national IDs
    When I lookup citizen record for national_id "CITIZEN111111"
    Then the response status should be 200
    And I save the response as "first_citizen"
    
    When I lookup citizen record for national_id "CITIZEN222222"
    Then the response status should be 200
    And the response field "full_name" should not equal the "first_citizen" full_name
    And the response field "national_id" should equal "CITIZEN222222"

    @registry @citizen @cache
  Scenario: Repeated citizen lookups use cache
    When I lookup citizen record for national_id "CACHED123456"
    Then the response status should be 200
    And I note the "checked_at" timestamp
    
    When I lookup citizen record for national_id "CACHED123456" again within 1 second
    Then the response status should be 200
    And the "checked_at" timestamp should be unchanged

    @registry @sanctions @normal
  Scenario: Successful sanctions check - not listed
    When I check sanctions for national_id "CLEAN123456"
    Then the response status should be 200
    And the response should contain "national_id"
    And the response should contain "listed"
    And the response should contain "source"
    And the response should contain "checked_at"
    And the response field "national_id" should equal "CLEAN123456"
    And the response field "listed" should equal false
    And the response field "source" should not be empty

    @registry @sanctions @normal
  Scenario: Sanctions check - user is listed
    When I check sanctions for national_id "SANCTIONED99"
    Then the response status should be 200
    And the response field "listed" should equal true
    And the response field "source" should not be empty

    @registry @sanctions @cache
  Scenario: Repeated sanctions checks use cache
    When I check sanctions for national_id "SANCHECK123"
    Then the response status should be 200
    And I note the "checked_at" timestamp
    
    When I check sanctions for national_id "SANCHECK123" again within 1 second
    Then the response status should be 200
    And the "checked_at" timestamp should be unchanged

    @registry @combined @normal
  Scenario: Perform both citizen and sanctions lookups for same ID
    When I lookup citizen record for national_id "COMBINED123"
    Then the response status should be 200
    And the response field "valid" should equal true
    
    When I check sanctions for national_id "COMBINED123"
    Then the response status should be 200
    And the response field "listed" should equal false

    @registry @citizen @validation
  Scenario: Citizen lookup without authentication
    When I lookup citizen record for national_id "TEST123456" without authentication
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @registry @citizen @validation
  Scenario: Citizen lookup without consent
    Given I revoke consent for purposes "registry_check"
    When I lookup citizen record for national_id "TEST123456"
    Then the response status should be 403
    And the response field "error" should equal "missing_consent"

    @registry @citizen @validation
  Scenario: Citizen lookup with empty national_id
    When I POST to "/registry/citizen" with empty national_id
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @registry @citizen @validation
  Scenario: Citizen lookup with invalid national_id format
    When I lookup citizen record for national_id "invalid!"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"
    And the response field "error_description" should contain "invalid format"

    @registry @citizen @validation
  Scenario: Citizen lookup with national_id too short
    When I lookup citizen record for national_id "ABC"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @registry @citizen @validation
  Scenario: Citizen lookup with national_id too long
    When I lookup citizen record for national_id "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @registry @sanctions @validation
  Scenario: Sanctions check without authentication
    When I check sanctions for national_id "TEST123456" without authentication
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @registry @sanctions @validation
  Scenario: Sanctions check without consent
    Given I revoke consent for purposes "registry_check"
    When I check sanctions for national_id "TEST123456"
    Then the response status should be 403
    And the response field "error" should equal "missing_consent"

    @registry @sanctions @validation
  Scenario: Sanctions check with empty national_id
    When I POST to "/registry/sanctions" with empty national_id
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @registry @sanctions @validation
  Scenario: Sanctions check with invalid national_id format
    When I check sanctions for national_id "invalid@#$"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @registry @citizen @not-found
  Scenario: Citizen lookup for non-existent record returns 404
    When I lookup citizen record for national_id "NOTFOUND999"
    Then the response status should be 404
    And the response field "error" should equal "not_found"
    And the response field "error_description" should contain "not found"

    @registry @citizen @invalid-record
  Scenario: Citizen lookup returns valid false for inactive record
    When I lookup citizen record for national_id "INVALID99999"
    Then the response status should be 200
    And the response field "valid" should equal false
    And the response should contain "checked_at"

    @registry @regulated
  Scenario: Citizen lookup in regulated mode returns minimized data
    Given the system is running in regulated mode
    When I lookup citizen record for national_id "REGULATED123"
    Then the response status should be 200
    And the response should contain "valid"
    And the response should contain "checked_at"
    And the response should not contain "full_name"
    And the response should not contain "date_of_birth"
    And the response should not contain "address"

    @registry @performance
  Scenario: Cache hit has low latency
    Given I lookup citizen record for national_id "PERF123456"
    When I lookup citizen record for national_id "PERF123456" and measure latency
    Then the response status should be 200
    And the response time should be less than 50 milliseconds

    @registry @idempotency
  Scenario: Multiple identical citizen lookups are idempotent
    When I lookup citizen record for national_id "IDEM123456"
    Then the response status should be 200
    And I save the full response as "first_lookup"
    
    When I lookup citizen record for national_id "IDEM123456"
    Then the response status should be 200
    And the response data should match "first_lookup"

    @registry @idempotency
  Scenario: Multiple identical sanctions checks are idempotent
    When I check sanctions for national_id "IDEMSANC123"
    Then the response status should be 200
    And I save the full response as "first_check"
    
    When I check sanctions for national_id "IDEMSANC123"
    Then the response status should be 200
    And the response data should match "first_check"

    @registry @audit
  Scenario: Registry lookups emit audit events
    When I lookup citizen record for national_id "AUDIT123456"
    Then the response status should be 200
    And an audit event should be emitted with action "registry_citizen_checked"
    And the audit event should contain user_id
    And the audit event should contain purpose "registry_check"

    @registry @audit
  Scenario: Sanctions checks emit audit events
    When I check sanctions for national_id "AUDITSANC123"
    Then the response status should be 200
    And an audit event should be emitted with action "registry_sanctions_checked"
    And the audit event should contain decision field

    @registry @error-handling
  Scenario: Registry timeout returns 504
    Given the citizen registry is configured with 10 second latency
    And the request timeout is set to 100 milliseconds
    When I lookup citizen record for national_id "TIMEOUT123"
    Then the response status should be 504
    And the response field "error" should equal "registry_timeout"

    @registry @error-handling
  Scenario: Cache expiry triggers fresh lookup
    Given I lookup citizen record for national_id "EXPIRE123"
    And I wait for 6 minutes
    When I lookup citizen record for national_id "EXPIRE123"
    Then the response status should be 200
    And the "checked_at" timestamp should be recent

    @registry @fallback
  Scenario: Primary provider failure triggers fallback
    Given the primary citizen registry provider returns 503
    When I lookup citizen record for national_id "FALLBACK123"
    Then the response status should be 200
    And the response field "valid" should equal true
    And the response field "source" should contain "fallback"

    @registry @fallback
  Scenario: All providers unavailable returns 500
    Given all citizen registry providers are unavailable
    When I lookup citizen record for national_id "ALLFAIL123"
    Then the response status should be 500
    And the response field "error" should equal "internal_error"
    And the response field "error_description" should contain "all registry providers failed"
