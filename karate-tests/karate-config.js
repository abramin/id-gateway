function fn() {
  // Get BASE_URL from system property or environment variable, default to localhost:8080
  var baseUrl =
    karate.properties['BASE_URL'] ||
    java.lang.System.getenv('BASE_URL') ||
    'http://localhost:8080';

  // Configuration object that will be available in all feature files
  var config = {
    baseUrl: baseUrl,

    // OAuth2 client configuration
    oauth: {
      clientId: 'test-client',
      clientSecret: 'test-secret',
      redirectUri: 'http://localhost:3000/callback',
      scope: 'openid profile email'
    },

    // Test user credentials
    testUser: {
      username: 'testuser@example.com',
      password: 'TestPassword123!'
    },

    // Common headers
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  };

  // Log configuration on startup
  karate.log('Base URL:', config.baseUrl);
  karate.log('Environment:', karate.env || 'not set');

  return config;
}
