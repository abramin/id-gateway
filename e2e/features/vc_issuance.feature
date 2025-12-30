Feature: Verifiable Credential Issuance
  As an authenticated user with valid identity
  I want to receive age verification credentials
  So that I can prove my age to third parties

  Background:
    Given the ID Gateway is running
    And I am authenticated as "vc-test@example.com"
    And I grant consent for purposes "vc_issuance,registry_check"

  # ============================================================================
  # Happy Path
  # ============================================================================

  @vc @normal
  Scenario: Issue AgeOver18 credential for eligible user
    Given the citizen registry contains a record for "ADULT123456" with birth date "1990-01-01"
    When I request an AgeOver18 credential with national_id "ADULT123456"
    Then the response status should be 200
    And the response should contain "credential_id"
    And the response field "type" should equal "AgeOver18"
    And the response field "issuer" should equal "credo"
    And the response should contain "issued_at"
    And the response should contain "claims"
    And the credential claims should contain "is_over_18" equal to true

  @vc @normal
  Scenario: Issued credential has valid ID format
    Given the citizen registry contains a record for "FMTCHECK123" with birth date "1985-06-15"
    When I request an AgeOver18 credential with national_id "FMTCHECK123"
    Then the response status should be 200
    And the response field "credential_id" should start with "vc_"

  # ============================================================================
  # Age Verification
  # ============================================================================

  @vc @age
  Scenario: Reject issuance for underage user (17 years old)
    Given the citizen registry contains a record for "MINOR17" with birth date making them 17 years old
    When I request an AgeOver18 credential with national_id "MINOR17"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"
    And the response field "error_description" should contain "age requirement"

  @vc @age
  Scenario: Issue credential for user who turned 18 today
    Given the citizen registry contains a record for "JUSTTURNED18" with birth date making them exactly 18 years old
    When I request an AgeOver18 credential with national_id "JUSTTURNED18"
    Then the response status should be 200
    And the credential claims should contain "is_over_18" equal to true

  # ============================================================================
  # Consent Enforcement
  # ============================================================================

  @vc @consent
  Scenario: Reject issuance without consent
    Given I am authenticated as "vc-no-consent@example.com"
    And I have NOT granted consent for purposes "vc_issuance"
    When I request an AgeOver18 credential with national_id "NOCONSENT123"
    Then the response status should be 403
    And the response field "error" should equal "missing_consent"

  @vc @consent
  Scenario: Reject issuance after consent revoked
    Given I am authenticated as "vc-revoked@example.com"
    And I grant consent for purposes "vc_issuance,registry_check"
    And I revoke consent for purposes "vc_issuance"
    When I request an AgeOver18 credential with national_id "REVOKED123"
    Then the response status should be 403
    And the response field "error" should equal "invalid_consent"

  # ============================================================================
  # Registry Errors
  # ============================================================================

  @vc @registry
  Scenario: Reject issuance for unknown citizen
    Given the citizen registry has no record for national_id "UNKNOWN999"
    When I request an AgeOver18 credential with national_id "UNKNOWN999"
    Then the response status should be 404
    And the response field "error" should equal "not_found"

  @vc @registry
  Scenario: Reject issuance for invalid citizen record
    Given the citizen registry contains an invalid record for "INVALID12345"
    When I request an AgeOver18 credential with national_id "INVALID12345"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"
    And the response field "error_description" should contain "invalid citizen"

  # ============================================================================
  # Validation Errors
  # ============================================================================

  @vc @validation
  Scenario: Reject issuance without authentication
    When I request an AgeOver18 credential with national_id "TEST123456" without authentication
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

  @vc @validation
  Scenario: Reject issuance with missing national_id
    When I POST to "/vc/issue" with empty national_id
    Then the response status should be 400
    And the response field "error" should equal "validation_error"
    And the response field "error_description" should contain "national_id is required"

  @vc @validation
  Scenario: Reject issuance with missing type
    When I POST to "/vc/issue" with missing type
    Then the response status should be 400
    And the response field "error" should equal "validation_error"
    And the response field "error_description" should contain "type is required"

  @vc @validation
  Scenario: Reject issuance with invalid credential type
    When I request a credential with invalid type "InvalidType" and national_id "TEST123456"
    Then the response status should be 400
    And the response field "error" should equal "validation_error"
    And the response field "error_description" should contain "type"

  @vc @validation
  Scenario: Reject issuance with invalid national_id format
    When I request an AgeOver18 credential with national_id "bad!"
    Then the response status should be 400
    And the response field "error" should equal "validation_error"
    And the response field "error_description" should contain "national_id"

  # ============================================================================
  # Regulated Mode (GDPR Compliance)
  # ============================================================================

  @vc @regulated
  Scenario: Regulated mode strips PII from credentials
    Given the system is running in regulated mode
    And the citizen registry contains a record for "REGULATED123" with birth date "1980-03-15"
    When I request an AgeOver18 credential with national_id "REGULATED123"
    Then the response status should be 200
    And the credential claims should contain "is_over_18" equal to true
    And the credential claims should NOT contain "verified_via"

  # Note: This scenario requires REGULATED_MODE=false which is not the default Docker config.
  # Use @unregulated tag to run against a non-regulated server configuration.
  @vc @unregulated
  Scenario: Non-regulated mode preserves verification source
    Given the system is NOT running in regulated mode
    And the citizen registry contains a record for "FULLDATA123" with birth date "1975-12-25"
    When I request an AgeOver18 credential with national_id "FULLDATA123"
    Then the response status should be 200
    And the credential claims should contain "is_over_18" equal to true
    And the credential claims should contain "verified_via"

  # ============================================================================
  # Audit Trail
  # ============================================================================

  # Note: Audit event verification requires internal access to the audit store.
  # This scenario is marked @pending until an audit query endpoint is available.
  @vc @audit @pending
  Scenario: VC issuance emits audit event
    Given the citizen registry contains a record for "AUDIT123456" with birth date "1988-07-20"
    When I request an AgeOver18 credential with national_id "AUDIT123456"
    Then the response status should be 200
    And an audit event should be emitted with action "vc_issued"
    And the audit event should contain purpose "vc_issuance"

  # ============================================================================
  # Idempotency
  # ============================================================================

  @vc @idempotency
  Scenario: Multiple issuance requests create separate credentials
    Given the citizen registry contains a record for "MULTI123456" with birth date "1992-04-10"
    When I request an AgeOver18 credential with national_id "MULTI123456"
    Then the response status should be 200
    And I save the response field "credential_id" as "first_credential"
    When I request an AgeOver18 credential with national_id "MULTI123456"
    Then the response status should be 200
    And the response field "credential_id" should not equal saved "first_credential"
