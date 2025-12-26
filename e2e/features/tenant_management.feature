Feature: Tenant & Client Management Admin API
    As a platform administrator
    I want to manage tenants and clients via admin API
    So that OAuth applications can be onboarded and configured

  Background:
    Given the ID Gateway is running

    # ============================================================
    # TENANT CRUD
    # ============================================================

    @admin @tenant @crud
  Scenario: Create tenant successfully
    When I create a tenant with name "Test Tenant E2E"
    Then the response status should be 201
    And the response should contain "tenant_id"
    And I save the tenant ID from the response

    @admin @tenant @crud
  Scenario: Create tenant with duplicate name fails
    When I create a tenant with exact name "Duplicate Tenant Test"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a tenant with exact name "Duplicate Tenant Test"
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    @admin @tenant @crud
  Scenario: Get tenant details
    When I create a tenant with name "Get Tenant Test"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I get the tenant details
    Then the response status should be 200
    And the response field "name" should contain "Get Tenant Test"

    @admin @tenant @validation
  Scenario: Create tenant with empty name fails
    When I create a tenant with name ""
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @tenant @security
  Scenario: Create tenant without admin token fails
    When I create a tenant with name "Unauthorized Tenant" and token ""
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    # ============================================================
    # CLIENT CRUD
    # ============================================================

    @admin @client @crud
  Scenario: Create client under tenant
    When I create a tenant with name "Client Test Tenant"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a client "Test App" under the tenant
    Then the response status should be 201
    And the response should contain "client_id"
    And the response should contain "client_secret"
    And I save the client ID from the response

    @admin @client @crud
  Scenario: Get client details
    When I create a tenant with name "Get Client Tenant"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a client "Get Client App" under the tenant
    Then the response status should be 201
    And I save the client ID from the response

    When I get the client details
    Then the response status should be 200
    And the response field "name" should equal "Get Client App"
    # Secret should NOT be returned on GET
    And the response should not contain "client_secret"

    @admin @client @crud
  Scenario: Update client
    When I create a tenant with name "Update Client Tenant"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a client "Original Name" under the tenant
    Then the response status should be 201
    And I save the client ID from the response

    When I update the client name to "Updated Name"
    Then the response status should be 200
    And the response field "name" should equal "Updated Name"

    @admin @client @security
  Scenario: Client secret rotation
    When I create a tenant with name "Secret Rotation Tenant"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a client "Rotation App" under the tenant
    Then the response status should be 201
    And I save the client ID from the response
    And I save the client secret from the response

    When I rotate the client secret
    Then the response status should be 200
    And the response should contain "client_secret"
    And the new secret should be different from the saved secret

    @admin @client @validation
  Scenario: Create client with invalid tenant fails
    When I create a client "Orphan App" under tenant "00000000-0000-0000-0000-000000000000"
    Then the response status should be 404
    And the response field "error" should equal "not_found"

    @admin @client @security
  Scenario: Create client without admin token fails
    When I create a tenant with name "Unauthorized Client Tenant"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a client "Unauthorized App" under the tenant without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    # ============================================================
    # TENANT LIFECYCLE (PRD-026B)
    # ============================================================

    @admin @tenant @lifecycle
  Scenario: Deactivate tenant blocks OAuth flows
    Given I create a tenant with name "Lifecycle Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Test App" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I save the OAuth client_id from the response
    When I deactivate the tenant
    Then the response status should be 200
    When I initiate authorization with the client
    Then the response status should be 400
    And the response field "error" should equal "invalid_client"

    @admin @tenant @lifecycle
  Scenario: Deactivate already-inactive tenant returns conflict
    Given I create a tenant with name "Already Inactive"
    And the response status should be 201
    And I save the tenant ID from the response
    When I deactivate the tenant
    Then the response status should be 200
    When I deactivate the tenant
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    @admin @tenant @lifecycle
  Scenario: Reactivate tenant restores OAuth flows
    Given I create a tenant with name "Reactivate Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Restore App" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I save the OAuth client_id from the response
    And I deactivate the tenant
    And the response status should be 200
    When I reactivate the tenant
    Then the response status should be 200
    When I initiate authorization with the client
    Then the response status should be 200

    @admin @tenant @lifecycle
  Scenario: Reactivate already-active tenant returns conflict
    Given I create a tenant with name "Already Active"
    And the response status should be 201
    And I save the tenant ID from the response
    When I reactivate the tenant
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    # ============================================================
    # CLIENT LIFECYCLE (PRD-026B)
    # ============================================================

    @admin @client @lifecycle
  Scenario: Deactivate client blocks OAuth flows
    Given I create a tenant with name "Client Lifecycle"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Deactivate Me" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I save the OAuth client_id from the response
    When I deactivate the client
    Then the response status should be 200
    When I initiate authorization with the client
    Then the response status should be 400
    And the response field "error" should equal "invalid_client"

    @admin @client @lifecycle
  Scenario: Deactivate already-inactive client returns conflict
    Given I create a tenant with name "Client Already Inactive"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Already Inactive Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I deactivate the client
    Then the response status should be 200
    When I deactivate the client
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    @admin @client @lifecycle
  Scenario: Reactivate client restores OAuth flows
    Given I create a tenant with name "Restore Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Restore Me" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I save the OAuth client_id from the response
    And I deactivate the client
    And the response status should be 200
    When I reactivate the client
    Then the response status should be 200
    When I initiate authorization with the client
    Then the response status should be 200

    @admin @client @lifecycle
  Scenario: Reactivate already-active client returns conflict
    Given I create a tenant with name "Client Already Active"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Already Active Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I reactivate the client
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    # ============================================================
    # LIFECYCLE SECURITY TESTS (PRD-026B)
    # ============================================================

    @admin @tenant @lifecycle @security
  Scenario: Deactivate tenant without admin token fails
    Given I create a tenant with name "Auth Test Tenant"
    And the response status should be 201
    And I save the tenant ID from the response
    When I deactivate the tenant without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @client @lifecycle @security
  Scenario: Deactivate client without admin token fails
    Given I create a tenant with name "Client Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Auth Test Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I deactivate the client without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @tenant @lifecycle
  Scenario: Deactivate non-existent tenant returns not found
    When I deactivate tenant with id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    Then the response status should be 404
    And the response field "error" should equal "not_found"

    @admin @client @lifecycle
  Scenario: Deactivate non-existent client returns not found
    When I deactivate client with id "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    Then the response status should be 404
    And the response field "error" should equal "not_found"

    # ============================================================
    # CLIENT VALIDATION (OAuth Security)
    # ============================================================

    @admin @client @validation @security
  Scenario: Public client cannot use client_credentials grant
    Given I create a tenant with name "Public Client Grant Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I create a public client "Public SPA" with client_credentials grant under the tenant
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @client @validation @security
  Scenario: Redirect URI rejects localhost subdomain bypass
    Given I create a tenant with name "Localhost Bypass Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I create a client with redirect URI "http://localhost.attacker.com/callback" under the tenant
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @tenant @validation
  Scenario: Tenant name uniqueness is case-insensitive
    When I create a tenant with exact name "CaseTest"
    Then the response status should be 201
    And I save the tenant ID from the response
    When I create a tenant with exact name "casetest"
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    # ============================================================
    # SECRET ROTATION EDGE CASES
    # ============================================================

    @admin @client @security
  Scenario: Rotate secret for public client fails
    Given I create a tenant with name "Public Client Rotation Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I create a public client "Public SPA" under the tenant
    Then the response status should be 201
    And I save the client ID from the response
    When I rotate the client secret
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @client @security
  Scenario: Old secret is invalidated after rotation
    Given I create a tenant with name "Secret Invalidation Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Rotation Invalidation App" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I save the client secret from the response
    And I save the OAuth client_id from the response
    When I rotate the client secret
    Then the response status should be 200
    When I authenticate with the old client secret
    Then the authentication should fail

    # ============================================================
    # ADDITIONAL SECURITY TESTS (Auth enforcement)
    # ============================================================

    @admin @tenant @security
  Scenario: Reactivate tenant without admin token fails
    Given I create a tenant with name "Reactivate Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I deactivate the tenant
    And the response status should be 200
    When I reactivate the tenant without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @client @security
  Scenario: Reactivate client without admin token fails
    Given I create a tenant with name "Client Reactivate Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Auth Test Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I deactivate the client
    And the response status should be 200
    When I reactivate the client without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @tenant @security
  Scenario: Get tenant without admin token fails
    Given I create a tenant with name "Get Tenant Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I get the tenant details without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @client @security
  Scenario: Get client without admin token fails
    Given I create a tenant with name "Get Client Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Get Auth Test Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I get the client details without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @client @security
  Scenario: Update client without admin token fails
    Given I create a tenant with name "Update Client Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Update Auth Test Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I update the client name to "New Name" without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    @admin @client @security
  Scenario: Rotate secret without admin token fails
    Given I create a tenant with name "Rotate Secret Auth Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Rotate Auth Test Client" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I rotate the client secret without admin token
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    # ============================================================
    # CLIENT UPDATE VALIDATION
    # ============================================================

    @admin @client @validation
  Scenario: Update client with invalid redirect URI fails
    Given I create a tenant with name "Update URI Validation Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "URI Update Test App" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I update the client with redirect URI "http://example.com/callback"
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @client @validation
  Scenario: Update public client to use client_credentials fails
    Given I create a tenant with name "Public Grant Update Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I create a public client "Public Grant Test" under the tenant
    Then the response status should be 201
    And I save the client ID from the response
    When I update the client with client_credentials grant
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @client @validation
  Scenario: Update client with empty name fails
    Given I create a tenant with name "Empty Name Update Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Empty Name Test App" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    When I update the client name to ""
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    # ============================================================
    # TENANT-CLIENT RELATIONSHIP
    # ============================================================

    @admin @client @lifecycle
  Scenario: Reactivating tenant does not auto-reactivate deactivated clients
    Given I create a tenant with name "Cascade Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I create a client "Cascade App" under the tenant
    And the response status should be 201
    And I save the client ID from the response
    And I save the OAuth client_id from the response
    And I deactivate the client
    And the response status should be 200
    And I deactivate the tenant
    And the response status should be 200
    When I reactivate the tenant
    Then the response status should be 200
    When I initiate authorization with the client
    Then the response status should be 400
    And the response field "error" should equal "invalid_client"

    # ============================================================
    # INACTIVE TENANT CLIENT CREATION
    # ============================================================

    @admin @client @lifecycle
  Scenario: Create client under inactive tenant fails
    Given I create a tenant with name "Inactive Tenant Client Test"
    And the response status should be 201
    And I save the tenant ID from the response
    And I deactivate the tenant
    And the response status should be 200
    When I create a client "Orphan Client" under the tenant
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    # ============================================================
    # NAME LENGTH BOUNDARY TESTS
    # ============================================================

    @admin @tenant @validation
  Scenario: Tenant name at max length succeeds
    When I create a tenant with name of exactly 128 characters
    Then the response status should be 201
    And I save the tenant ID from the response

    @admin @tenant @validation
  Scenario: Tenant name exceeds max length fails
    When I create a tenant with name of exactly 129 characters
    Then the response status should be 400
    And the response field "error" should equal "validation_error"

    @admin @client @validation
  Scenario: Client name at max length succeeds
    Given I create a tenant with name "Client Name Length Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I create a client with name of exactly 128 characters under the tenant
    Then the response status should be 201

    @admin @client @validation
  Scenario: Client name exceeds max length fails
    Given I create a tenant with name "Client Name Overflow Test"
    And the response status should be 201
    And I save the tenant ID from the response
    When I create a client with name of exactly 129 characters under the tenant
    Then the response status should be 400
    And the response field "error" should equal "validation_error"
