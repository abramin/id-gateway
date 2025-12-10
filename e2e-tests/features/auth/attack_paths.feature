Feature: OAuth2 Security Attack Paths - Simulated Tests

  Background:
    Given the API base URL is configured
    And OAuth2 client credentials are available

    @security @simulation
  Scenario: Intercepted authorization code attack (simulation)
    # This is a documentation/planning scenario for PKCE implementation
    Given PKCE is not yet implemented
    Then log "[SIMULATION ONLY] Testing authorization code interception vulnerability"
    And log "[ATTACK VECTOR] Attacker intercepts authorization code from redirect URL"
    And log "[MITIGATION] PKCE should prevent this attack by requiring code_verifier"
    And log "[TODO] Update this test when PKCE is added to the API"

    @security @simulation
  Scenario: Redirect URI manipulation attack (simulation)
    Given strict redirect URI validation is not yet enforced
    Then log "[SIMULATION ONLY] Testing redirect_uri manipulation vulnerability"
    And log "[ATTACK VECTOR] Attacker modifies redirect_uri to steal authorization code"
    And log "[MITIGATION] Strict redirect_uri validation should be implemented"
    And log "[TODO] Implement redirect_uri allowlist validation per client"

    @security @simulation
  Scenario: Missing PKCE parameters (simulation)
    Given PKCE is not yet implemented
    Then log "[SIMULATION ONLY] Testing missing PKCE vulnerability"
    And log "[ATTACK VECTOR] Client attempts authorization without PKCE"
    And log "[MITIGATION] Require PKCE for public clients"

    @security @simulation
  Scenario: Invalid PKCE code challenge method (simulation)
    Given PKCE is not yet implemented
    Then log "[SIMULATION ONLY] Testing weak PKCE challenge method"
    And log "[ATTACK VECTOR] Client uses plain PKCE instead of S256"
    And log "[MITIGATION] Only allow S256 code challenge method"

    @security @simulation
  Scenario: Token leakage via referer header (simulation)
    Given the API uses authorization code flow
    Then log "[SIMULATION ONLY] Testing token leakage vulnerability"
    And log "[ATTACK VECTOR] Tokens leaked via Referer header or browser history"
    And log "[MITIGATION] Use authorization code flow, not implicit flow"
    And log "[STATUS] Current API uses authorization code flow (good)"
    And log "[NOTE] Implicit flow is deprecated and should never be implemented"

    @security @simulation
  Scenario: State parameter missing - CSRF attack (simulation)
    Given state parameter is optional in current implementation
    Then log "[SIMULATION ONLY] Testing CSRF vulnerability"
    And log "[ATTACK VECTOR] Authorization request without state parameter"
    And log "[MITIGATION] State parameter should be validated by client"
    And log "[NOTE] State validation is client-side responsibility"

    @security @simulation
  Scenario: Authorization code reuse attack (covered in normal_flow.feature)
    Given authorization codes are single-use
    Then log "[SIMULATION ONLY] Testing authorization code reuse vulnerability"
    And log "[ATTACK VECTOR] Attempt to use same authorization code multiple times"
    And log "[MITIGATION] Authorization codes must be single-use only"
    And log "[STATUS] This is tested in normal_flow.feature - code reuse scenario"

    @security @simulation
  Scenario: Client secret exposure in public client (simulation)
    Given the API does not require client_secret
    Then log "[SIMULATION ONLY] Testing client authentication for public clients"
    And log "[ATTACK VECTOR] Public client should not rely on client_secret"
    And log "[MITIGATION] Use PKCE instead of client_secret for public clients"
    And log "[STATUS] Current API does not require client_secret (good)"
    And log "[TODO] When PKCE is implemented, enforce it for public clients"
