Feature: Verifiable Credential Verification
  As an authenticated user
  I want to verify issued credentials
  So that I can reuse proof without re-checking registry data

  Background:
    Given the ID Gateway is running
    And I am authenticated as "vc-verify@example.com"
    And I grant consent for purposes "vc_issuance,registry_check"

  # ============================================================================
  # Happy Path
  # ============================================================================

  @vc @verify
  Scenario: Verify an issued AgeOver18 credential
    Given the citizen registry contains a record for "VERIFY123456" with birth date "1990-01-01"
    When I request an AgeOver18 credential with national_id "VERIFY123456"
    Then the response status should be 200
    And I save the response field "credential_id" as "issued_credential"
    When I verify the saved credential_id "issued_credential"
    Then the response status should be 200
    And the response field "valid" should equal "true"
    And the response should contain "credential_id"
    And the response should contain "claims"
    And the credential claims should contain "is_over_18" equal to true

  # ============================================================================
  # Not Found
  # ============================================================================

  @vc @verify
  Scenario: Reject verification for unknown credential
    When I verify a credential with id "vc_00000000-0000-0000-0000-000000000000"
    Then the response status should be 404
    And the response field "valid" should equal "false"
    And the response field "reason" should equal "credential_not_found"

  # ============================================================================
  # Validation Errors
  # ============================================================================

  @vc @verify @validation
  Scenario: Reject verification with missing credential_id
    When I POST to "/vc/verify" with empty credential_id
    Then the response status should be 400
    And the response field "error" should equal "validation_error"
    And the response field "error_description" should contain "credential_id is required"

  @vc @verify @validation
  Scenario: Reject verification without authentication
    When I verify a credential with id "vc_00000000-0000-0000-0000-000000000000" without authentication
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

  # ============================================================================
  # Audit Trail
  # ============================================================================

  # Note: Audit event verification requires internal access to the audit store.
  # This scenario is marked @pending until an audit query endpoint is available.
  @vc @audit @pending
  Scenario: VC verification emits audit event
    Given the citizen registry contains a record for "VERIFYAUDIT123" with birth date "1991-08-10"
    When I request an AgeOver18 credential with national_id "VERIFYAUDIT123"
    Then the response status should be 200
    And I save the response field "credential_id" as "audit_credential"
    When I verify the saved credential_id "audit_credential"
    Then the response status should be 200
    And an audit event should be emitted with action "vc_verified"
    And the audit event should contain purpose "vc_verification"
