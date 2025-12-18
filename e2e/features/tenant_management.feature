Feature: Tenant & Client Management Admin API (PRD-026A)
    As a platform administrator
    I want to manage tenants and clients via admin API
    So that OAuth applications can be onboarded and configured

  Background:
    Given the ID Gateway is running

    # ============================================================
    # TENANT CRUD (PRD-026A FR-1, FR-2)
    # ============================================================

    @admin @tenant @crud
  Scenario: Create tenant successfully
    When I create a tenant with name "Test Tenant E2E"
    Then the response status should be 201
    And the response should contain "tenant_id"
    And I save the tenant ID from the response

    @admin @tenant @crud
  Scenario: Create tenant with duplicate name fails (PRD-026A FR-1)
    When I create a tenant with name "Duplicate Tenant Test"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a tenant with name "Duplicate Tenant Test"
    Then the response status should be 409
    And the response field "error" should equal "conflict"

    @admin @tenant @crud
  Scenario: Get tenant details (PRD-026A FR-2)
    When I create a tenant with name "Get Tenant Test"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I get the tenant details
    Then the response status should be 200
    And the response field "name" should equal "Get Tenant Test"

    @admin @tenant @validation
  Scenario: Create tenant with empty name fails
    When I create a tenant with name ""
    Then the response status should be 400
    And the response field "error" should equal "validation"

    @admin @tenant @security
  Scenario: Create tenant without admin token fails
    When I create a tenant with name "Unauthorized Tenant" and token ""
    Then the response status should be 401
    And the response field "error" should equal "unauthorized"

    # ============================================================
    # CLIENT CRUD (PRD-026A FR-3, FR-4)
    # ============================================================

    @admin @client @crud
  Scenario: Create client under tenant (PRD-026A FR-3)
    When I create a tenant with name "Client Test Tenant"
    Then the response status should be 201
    And I save the tenant ID from the response

    When I create a client "Test App" under the tenant
    Then the response status should be 201
    And the response should contain "client_id"
    And the response should contain "client_secret"
    And I save the client ID from the response

    @admin @client @crud
  Scenario: Get client details (PRD-026A FR-4)
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
    And the response field "client_secret" should equal ""

    @admin @client @crud
  Scenario: Update client (PRD-026A FR-4)
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
  Scenario: Client secret rotation (PRD-026A FR-4)
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
