Feature: Consent Management
    As an authenticated user
    I want to manage my consent for different purposes
    So that I can control how my data is processed

  Background:
    Given the ID Gateway is running
    And I am authenticated as "consent-test@example.com"

      @consent @normal
  Scenario: Grant consent for multiple purposes
    When I grant consent for purposes "login,registry_check,vc_issuance"
    Then the response status should be 200
    And the response should contain "granted"
    And the response field "message" should contain "Consent granted for 3 purposes"
    And each granted consent should have "status" equal to "active"
    And each granted consent should have "granted_at"
    And each granted consent should have "expires_at"

      @consent @normal
  Scenario: List all consents
    Given I grant consent for purposes "login,registry_check"
    When I list my consents
    Then the response status should be 200
    And the response should contain "consents"
    And the response should contain at least 2 consent records

      @consent @normal
  Scenario: Revoke specific consent
    Given I grant consent for purposes "login,registry_check,vc_issuance"
    When I revoke consent for purposes "registry_check"
    Then the response status should be 200
    And the response should contain "revoked"
    And the response field "message" should contain "Consent revoked for 1 purpose"
    And the revoked consent should have "status" equal to "revoked"
    And the revoked consent should have "revoked_at"

      @consent @normal
  Scenario: List consents shows correct statuses after revocation
    Given I grant consent for purposes "login,registry_check"
    And I revoke consent for purposes "registry_check"
    When I list my consents
    Then the response status should be 200
    And the consent for purpose "login" should have status "active"
    And the consent for purpose "registry_check" should have status "revoked"

      @consent @normal
  Scenario: Re-grant previously revoked consent
    Given I grant consent for purposes "login"
    And I revoke consent for purposes "login"
    When I grant consent for purposes "login"
    Then the response status should be 200
    And the consent for purpose "login" should have status "active"
    And the consent should have a new "granted_at" timestamp

      @consent @validation
  Scenario: Grant consent without authentication
    When I grant consent for purposes "login" without authentication
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

      @consent @validation
  Scenario: Grant consent with empty purposes array
    When I POST to "/auth/consent" with empty purposes array
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

      @consent @validation
  Scenario: Grant consent with invalid purpose
    When I grant consent for purposes "invalid_purpose"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

      @consent @validation
  Scenario: Revoke consent without authentication
    When I revoke consent for purposes "login" without authentication
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

      @consent @validation
  Scenario: Revoke consent with invalid purpose
    When I revoke consent for purposes "invalid_purpose"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

      @consent @validation
  Scenario: List consents without authentication
    When I GET "/auth/consent" without authorization
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

      @consent @idempotency
  Scenario: Revoke already revoked consent is idempotent
    Given I grant consent for purposes "login"
    And I revoke consent for purposes "login"
    When I revoke consent for purposes "login"
    Then the response status should be 200

      @consent @idempotency
  Scenario: Grant consent renews existing active consent
    Given I grant consent for purposes "login"
    And I wait 2 seconds
    When I grant consent for purposes "login"
    Then the response status should be 200
    And the consent should have a new "granted_at" timestamp
    And the consent should have a new "expires_at" timestamp

  # ============================================================================
  # Filter Tests
  # ============================================================================

      @consent @filter
  Scenario: Filter consents by status - active only
    Given I revoke all my consents
    And I grant consent for purposes "login,registry_check"
    And I revoke consent for purposes "registry_check"
    When I list my consents filtered by status "active"
    Then the response status should be 200
    And all consents should have status "active"
    And the response should contain 1 consent records

      @consent @filter
  Scenario: Filter consents by status - revoked only
    Given I revoke all my consents
    And I grant consent for purposes "login,registry_check"
    And I revoke consent for purposes "registry_check"
    When I list my consents filtered by status "revoked"
    Then the response status should be 200
    And all consents should have status "revoked"
    And the response should contain 1 consent records

      @consent @filter
  Scenario: Filter consents by purpose
    Given I revoke all my consents
    And I grant consent for purposes "login,registry_check,vc_issuance"
    When I list my consents filtered by purpose "login"
    Then the response status should be 200
    And all consents should have purpose "login"
    And the response should contain 1 consent records

      @consent @filter
  Scenario: Filter consents by status and purpose combined
    Given I revoke all my consents
    And I grant consent for purposes "login,registry_check"
    And I revoke consent for purposes "login"
    When I list my consents filtered by status "active" and purpose "registry_check"
    Then the response status should be 200
    And all consents should have status "active"
    And all consents should have purpose "registry_check"

      @consent @filter @validation
  Scenario: Filter with invalid status returns error
    When I list my consents filtered by status "invalid_status"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

      @consent @filter @validation
  Scenario: Filter with invalid purpose returns error
    When I list my consents filtered by purpose "invalid_purpose"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

  # ============================================================================
  # All Consent Purposes Coverage
  # ============================================================================

      @consent @purposes
  Scenario: Grant consent for all four purposes
    When I grant consent for purposes "login,registry_check,vc_issuance,decision_evaluation"
    Then the response status should be 200
    And the response field "message" should contain "Consent granted for 4 purposes"
    And the consent for purpose "login" should have status "active"
    And the consent for purpose "registry_check" should have status "active"
    And the consent for purpose "vc_issuance" should have status "active"
    And the consent for purpose "decision_evaluation" should have status "active"

      @consent @purposes
  Scenario: Grant and revoke decision_evaluation consent
    Given I grant consent for purposes "decision_evaluation"
    When I revoke consent for purposes "decision_evaluation"
    Then the response status should be 200
    And the revoked consent should have "status" equal to "revoked"
    When I list my consents
    Then the consent for purpose "decision_evaluation" should have status "revoked"

      @consent @purposes
  Scenario: Re-grant decision_evaluation after revocation
    Given I grant consent for purposes "decision_evaluation"
    And I revoke consent for purposes "decision_evaluation"
    When I grant consent for purposes "decision_evaluation"
    Then the response status should be 200
    And the consent for purpose "decision_evaluation" should have status "active"

  # ============================================================================
  # Edge Cases
  # ============================================================================

      @consent @edge
  Scenario: Revoke non-existent consent is idempotent
    When I revoke consent for purposes "vc_issuance"
    Then the response status should be 200
    # Should not error, just return empty revoked list

      @consent @edge
  Scenario: List consents when none granted returns empty array
    # Note: Using a fresh user to ensure no prior consents
    Given I am authenticated as "fresh-consent-user@example.com"
    When I list my consents
    Then the response status should be 200
    And the response should contain "consents"
    And the response should contain 0 consent records

  # ============================================================================
  # GDPR Delete Tests
  # ============================================================================

      @consent @gdpr
  Scenario: Delete all consents removes all records
    Given I am authenticated as "gdpr-delete-test@example.com"
    And I grant consent for purposes "login,registry_check,vc_issuance"
    When I delete all my consents
    Then the response status should be 200
    And the response field "message" should equal "All consents deleted"
    When I list my consents
    Then the response status should be 200
    And the response should contain 0 consent records

      @consent @gdpr
  Scenario: Delete all consents removes both active and revoked records
    Given I am authenticated as "gdpr-mixed-test@example.com"
    And I grant consent for purposes "login,registry_check"
    And I revoke consent for purposes "registry_check"
    When I delete all my consents
    Then the response status should be 200
    When I list my consents
    Then the response status should be 200
    And the response should contain 0 consent records

      @consent @gdpr @validation
  Scenario: Delete all consents without authentication
    When I DELETE "/auth/consent" without authorization
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

  # ============================================================================
  # Consent Enforcement (Require)
  # ============================================================================
  # Note: Consent enforcement via Require() is tested in registry_flow.feature:
  #   - "Citizen lookup without consent" (403 missing_consent)
  #   - "Sanctions check without consent" (403 missing_consent)
  # Expired consent enforcement is tested in integration_test.go via time manipulation.

      @consent @enforcement
  Scenario: Operations requiring consent fail when consent revoked
    Given I am authenticated as "enforcement-test@example.com"
    And I have granted consent for purposes "registry_check"
    When I lookup citizen record for national_id "ENFORCE123"
    Then the response status should be 200
    When I revoke consent for purposes "registry_check"
    And I lookup citizen record for national_id "ENFORCE456"
    Then the response status should be 403
    And the response field "error" should equal "missing_consent"
