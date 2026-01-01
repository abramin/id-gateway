Feature: Decision Engine Evaluation
  As an authenticated user
  I want to evaluate identity decisions based on business rules
  So that I can verify compliance requirements without handling PII

  Background:
    Given the ID Gateway is running
    And I am authenticated as "decision-test@example.com"
    And I grant consent for purposes "decision_evaluation,registry_check"

  # =============================================
  # Age Verification - Happy Paths
  # =============================================

  @decision @age-verification @normal
  Scenario: Age verification passes with existing credential
    Given the citizen registry contains a record for "ADULT123456" with birth date "1990-01-15"
    And I request an AgeOver18 credential with national_id "ADULT123456"
    When I evaluate "age_verification" for national_id "ADULT123456"
    Then the response status should be 200
    And the decision status should be "pass"
    And the decision reason should be "all_checks_passed"
    And the evidence field "is_over_18" should be true
    And the evidence field "citizen_valid" should be true
    And the evidence field "has_credential" should be true
    And the evidence field "sanctions_listed" should be false

  @decision @age-verification @normal
  Scenario: Age verification passes with conditions when no credential
    Given the citizen registry contains a record for "NOCRED123456" with birth date "1990-01-15"
    When I evaluate "age_verification" for national_id "NOCRED123456"
    Then the response status should be 200
    And the decision status should be "pass_with_conditions"
    And the decision reason should be "missing_credential"
    And the conditions should include "obtain_age_credential"
    And the evidence field "is_over_18" should be true
    And the evidence field "citizen_valid" should be true
    And the evidence field "has_credential" should be false

  # =============================================
  # Age Verification - Failure Cases (Rule Chain)
  # =============================================

  @decision @age-verification @failure
  Scenario: Age verification fails when user is sanctioned (Rule 1)
    Given the citizen registry contains a record for "SANCTIONED123" with birth date "1990-01-15"
    And the sanctions registry marks "SANCTIONED123" as listed
    When I evaluate "age_verification" for national_id "SANCTIONED123"
    Then the response status should be 200
    And the decision status should be "fail"
    And the decision reason should be "sanctioned"
    And the evidence field "sanctions_listed" should be true

  @decision @age-verification @failure
  Scenario: Age verification fails when citizen record is invalid (Rule 2)
    Given the citizen registry contains an invalid record for "INVALID123456"
    When I evaluate "age_verification" for national_id "INVALID123456"
    Then the response status should be 200
    And the decision status should be "fail"
    And the decision reason should be "invalid_citizen"
    And the evidence field "citizen_valid" should be false

  @decision @age-verification @failure
  Scenario: Age verification fails when user is underage (Rule 3)
    Given the citizen registry contains a record for "MINOR123456" with birth date making them 16 years old
    When I evaluate "age_verification" for national_id "MINOR123456"
    Then the response status should be 200
    And the decision status should be "fail"
    And the decision reason should be "underage"
    And the evidence field "is_over_18" should be false
    And the evidence field "citizen_valid" should be true

  @decision @age-verification @edge
  Scenario: Age verification passes for user exactly 18 years old
    Given the citizen registry contains a record for "EXACT18" with birth date making them exactly 18 years old
    When I evaluate "age_verification" for national_id "EXACT18"
    Then the response status should be 200
    And the decision status should be "pass_with_conditions"
    And the evidence field "is_over_18" should be true

  # =============================================
  # Sanctions Screening
  # =============================================

  @decision @sanctions @normal
  Scenario: Sanctions screening passes when not listed
    Given the citizen registry contains a record for "CLEAN123456" with birth date "1990-01-15"
    When I evaluate "sanctions_screening" for national_id "CLEAN123456"
    Then the response status should be 200
    And the decision status should be "pass"
    And the decision reason should be "not_sanctioned"
    And the evidence field "sanctions_listed" should be false

  @decision @sanctions @failure
  Scenario: Sanctions screening fails when listed
    Given the sanctions registry marks "SANCTIONED999" as listed
    When I evaluate "sanctions_screening" for national_id "SANCTIONED999"
    Then the response status should be 200
    And the decision status should be "fail"
    And the decision reason should be "sanctioned"
    And the evidence field "sanctions_listed" should be true

  # =============================================
  # Consent Enforcement
  # =============================================

  @decision @consent @failure
  Scenario: Evaluation fails without decision_evaluation consent
    Given I have revoked consent for purposes "decision_evaluation"
    When I evaluate "age_verification" for national_id "TEST123456"
    Then the response status should be 403

  # =============================================
  # Validation Errors
  # =============================================

  @decision @validation
  Scenario: Evaluation fails with invalid purpose
    When I evaluate "invalid_purpose" for national_id "TEST123456"
    Then the response status should be 400
    And the response should contain "unsupported purpose"

  @decision @validation
  Scenario: Evaluation fails without national_id
    When I evaluate "age_verification" without national_id
    Then the response status should be 400
    And the response should contain "national_id is required"

  @decision @validation
  Scenario: Evaluation fails without authentication
    When I evaluate "age_verification" for national_id "TEST123456" without authentication
    Then the response status should be 401

  @decision @validation
  Scenario: Evaluation fails with empty purpose
    When I evaluate "" for national_id "TEST123456"
    Then the response status should be 400
    And the response should contain "purpose is required"
