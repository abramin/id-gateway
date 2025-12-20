Feature: Admin GDPR User Deletion (PRD-001B)
    As a system administrator
    I want to delete users and their sessions for GDPR compliance
    So that I can fulfill data erasure requests

  Background:
    Given the ID Gateway is running

    @admin @gdpr
  Scenario: Admin successfully deletes user and sessions
    # Create a user with an active session
    When I initiate authorization with email "gdpr-delete@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200
    And the response should contain "access_token"

    When I request user info with the access token
    Then the response status should be 200
    And the response field "email" should equal "gdpr-delete@example.com"
    And I save the user ID from the userinfo response

    # Delete the user via admin API
    When I delete the user via admin API
    Then the response status should be 204

    # Verify user is deleted - session should no longer work
    When I attempt to get user info with the saved access token
    Then the response status should be 401

    @admin @gdpr @validation
  Scenario: Admin deletion with invalid user ID returns 400
    When I attempt to delete user with ID "invalid-uuid" via admin API
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @admin @gdpr @validation
  Scenario: Admin deletion with non-existent user ID returns 404
    When I attempt to delete user with ID "11111111-1111-1111-1111-111111111111" via admin API
    Then the response status should be 404
    And the response field "error" should equal "not_found"

    @admin @gdpr @security
  Scenario: Admin deletion without admin token returns 401
    When I initiate authorization with email "unauthorized-delete@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200

    When I request user info with the access token
    Then the response status should be 200
    And I save the user ID from the userinfo response

    When I delete the user via admin API with token ""
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @gdpr @security
  Scenario: Admin deletion with wrong admin token returns 401
    When I initiate authorization with email "wrong-token-delete@example.com" and scopes "openid"
    Then the response status should be 200
    And I save the authorization code

    When I exchange the authorization code for tokens
    Then the response status should be 200

    When I request user info with the access token
    Then the response status should be 200
    And I save the user ID from the userinfo response

    When I delete the user via admin API with token "wrong-admin-token"
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"
