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
