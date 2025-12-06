Feature: Auth test suite entrypoint

  Scenario: Run normal auth flows
    * call read('classpath:idgateway/auth/normal_flow.feature')

  Scenario: Run security attack path simulations
    * call read('classpath:idgateway/auth/attack_paths.feature')
