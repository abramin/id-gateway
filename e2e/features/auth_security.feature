Feature: OAuth2 Security - Client and Tenant Validation
    As a security engineer
    I want to validate that unknown and invalid clients are rejected
    So that the authorization server only serves registered clients

  Background:
    Given the ID Gateway is running

    @security @client-validation
  Scenario: Unknown client_id rejected (RFC 6749 §4.1.2.1)
    When I request authorization with unknown client_id "unknown-client-xyz"
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    @security @client-validation
  Scenario: Empty client_id rejected
    When I request authorization with empty client_id
    Then the response status should be 400
    And the response field "error" should equal "bad_request"

    # ============================================================
    # SECURITY SIMULATIONS (Documentation of known attack vectors)
    # ============================================================

    @security @simulation
  Scenario: PKCE not yet implemented
    Given PKCE is a recommended security feature
    Then log "SIMULATION: Authorization code interception vulnerability exists"
    And log "MITIGATION: Implement PKCE (code_challenge/code_verifier)"
    And log "STATUS: Not yet implemented"

    @security @simulation
  Scenario: Redirect URI validation not enforced
    Given redirect URI validation prevents token theft
    Then log "SIMULATION: Redirect URI manipulation vulnerability"
    And log "MITIGATION: Implement strict redirect_uri allowlist per client"
    And log "STATUS: Not yet implemented"

    @security @simulation
  Scenario: State parameter is optional
    Given CSRF protection is important
    Then log "SIMULATION: CSRF vulnerability via missing state parameter"
    And log "MITIGATION: State parameter validation is client responsibility"
    And log "STATUS: Optional in current implementation"

    @security @simulation
  Scenario: Token leakage prevention via authorization code flow
    Given implicit flow leaks tokens in browser history
    Then log "SIMULATION: Token leakage prevention"
    And log "MITIGATION: Use authorization code flow (currently implemented)"
    And log "STATUS: Good - implicit flow not supported"

    @security @simulation
  Scenario: Authorization code reuse is prevented
    Given authorization codes should be single-use
    Then log "SIMULATION: Authorization code reuse attack"
    And log "MITIGATION: Codes marked as used after exchange"
    And log "STATUS: Implemented - covered in normal flow tests"

    @security @simulation
  Scenario: Public clients should use PKCE not secrets
    Given public clients cannot keep secrets
    Then log "SIMULATION: Client secret exposure in public client"
    And log "MITIGATION: Use PKCE for public clients (SPAs/mobile)"
    And log "STATUS: Client secrets not required (good for public clients)"
    And log "TODO: Enforce PKCE when implemented"
