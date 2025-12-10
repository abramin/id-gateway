Feature: OAuth2 Security - Attack Path Simulations
    As a security engineer
    I want to document known attack vectors
    So that future implementations address these threats

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
