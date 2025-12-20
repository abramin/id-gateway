// k6 Load Test Suite for Credo OAuth Server
//
// Usage: k6 run loadtest/k6-credo.js
//
// The script is self-bootstrapping in local/dev environments - no config needed.
// It automatically creates a tenant, client, and test users on each run.
//
// Environment variables (all optional):
//   BASE_URL       - Server URL (default: http://localhost:8080)
//   ADMIN_TOKEN    - Admin API token (default: demo-admin-token)
//   CLIENT_ID      - Use existing client (skips tenant/client creation)
//   TENANT_ID      - Use existing tenant for client creation
//   REDIRECT_URI   - Redirect URI (default: http://localhost:3000/demo/callback.html)
//   SCOPES         - Comma-separated scopes (default: openid,profile)
//   USER_COUNT     - Number of test users (default: 100)
//   SCENARIO       - Which scenario: token_refresh_storm | consent_burst | mixed_load | all

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const tokenRefreshLatency = new Trend('token_refresh_latency', true);
const consentGrantLatency = new Trend('consent_grant_latency', true);
const sessionListLatency = new Trend('session_list_latency', true);
const oauthFlowLatency = new Trend('oauth_flow_latency', true);
const authorizeLatency = new Trend('authorize_latency', true);
const tokenExchangeLatency = new Trend('token_exchange_latency', true);
const tokenErrors = new Counter('token_errors');
const consentErrors = new Counter('consent_errors');
const oauthFlowErrors = new Counter('oauth_flow_errors');
const errorRate = new Rate('error_rate');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
// Default to demo-admin-token matching server's default for local/dev environments
const ADMIN_TOKEN = __ENV.ADMIN_TOKEN || 'demo-admin-token';
const CLIENT_ID = __ENV.CLIENT_ID || '';
const SCENARIO = __ENV.SCENARIO || 'all';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'http://localhost:3000/demo/callback.html';
const DEFAULT_SCOPES = parseScopes(__ENV.SCOPES || 'openid,profile');
// Max VUs across all scenarios - each VU needs its own token to avoid refresh token contention
const MAX_VUS = 200;
const USER_COUNT = parsePositiveInt(__ENV.USER_COUNT, MAX_VUS);

const CONSENT_PURPOSES = ['login', 'registry_check', 'vc_issuance', 'decision_evaluation'];

// Scenario configurations
export const options = {
  scenarios: {
    // Scenario 1: Token Refresh Storm
    // Tests mutex contention under concurrent token refresh load
    token_refresh_storm: {
      executor: 'constant-arrival-rate',
      rate: 100,                    // 100 requests per second
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'tokenRefreshScenario',
      startTime: '0s',
      tags: { scenario: 'token_refresh' },
    },

    // Scenario 2: Consent Grant Burst
    // Tests consent service throughput with multi-purpose grants
    consent_burst: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 100,
      stages: [
        { duration: '1m', target: 50 },   // Ramp up
        { duration: '3m', target: 50 },   // Sustained load
        { duration: '1m', target: 0 },    // Ramp down
      ],
      exec: 'consentBurstScenario',
      startTime: '0s',
      tags: { scenario: 'consent_burst' },
    },

    // Scenario 3: Mixed Load (Read + Write contention)
    // Tests read performance during write contention
    mixed_load: {
      executor: 'constant-vus',
      vus: 50,
      duration: '5m',
      exec: 'mixedLoadScenario',
      startTime: '0s',
      tags: { scenario: 'mixed_load' },
    },

    // Scenario 4: OAuth Flow Storm
    // Tests the full authorize → token exchange path under concurrent load.
    // This exercises sharded transactions in both authorize.go and token_exchange.go,
    // plus JWT generation outside transaction boundaries.
    oauth_flow_storm: {
      executor: 'constant-arrival-rate',
      rate: 50,                     // 50 full OAuth flows per second
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 50,
      maxVUs: 150,
      exec: 'oauthFlowScenario',
      startTime: '0s',
      tags: { scenario: 'oauth_flow' },
    },
  },

  thresholds: {
    // Token refresh: p95 < 200ms, error rate < 0.1%
    'token_refresh_latency{scenario:token_refresh}': ['p(95)<200'],
    'error_rate{scenario:token_refresh}': ['rate<0.001'],

    // Consent grants: p95 < 300ms
    'consent_grant_latency{scenario:consent_burst}': ['p(95)<300'],

    // Mixed load: both reads and writes should be responsive
    'session_list_latency{scenario:mixed_load}': ['p(95)<100'],
    'token_refresh_latency{scenario:mixed_load}': ['p(95)<300'],

    // OAuth flow: full authorize → exchange path
    'oauth_flow_latency{scenario:oauth_flow}': ['p(95)<500'],
    'authorize_latency{scenario:oauth_flow}': ['p(95)<200'],
    'token_exchange_latency{scenario:oauth_flow}': ['p(95)<300'],
  },
};

// Filter scenarios based on SCENARIO env var
if (SCENARIO !== 'all') {
  const selectedScenario = options.scenarios[SCENARIO];
  if (selectedScenario) {
    options.scenarios = { [SCENARIO]: selectedScenario };
  }
}

// Setup: Create test users and get tokens
export function setup() {
  console.log(`Starting load test against ${BASE_URL}`);
  console.log(`Running scenario: ${SCENARIO}`);

  const tenantName = __ENV.TENANT_NAME || `k6-tenant-${Date.now()}`;
  const clientName = __ENV.CLIENT_NAME || `k6-client-${Date.now()}`;
  let tenantID = __ENV.TENANT_ID || '';
  let clientID = CLIENT_ID;

  if (!clientID) {
    if (!ADMIN_TOKEN) {
      throw new Error('CLIENT_ID or ADMIN_TOKEN is required to bootstrap tokens');
    }
    if (!tenantID) {
      tenantID = createTenant(tenantName, ADMIN_TOKEN);
    }
    clientID = createClient(tenantID, clientName, REDIRECT_URI, DEFAULT_SCOPES, ADMIN_TOKEN);
  }

  const tokens = [];
  const users = [];
  for (let i = 0; i < USER_COUNT; i++) {
    const email = `loadtest+${i}@example.com`;
    const authCode = authorizeUser(email, clientID, REDIRECT_URI, DEFAULT_SCOPES);
    const token = exchangeCode(authCode, clientID, REDIRECT_URI);
    tokens.push({
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      userEmail: email,
    });
    users.push({ email });
  }

  return {
    tokens,
    users,
    clientID,
  };
}

function createTenant(name, adminToken) {
  const res = postJSON(
    `${BASE_URL}/admin/tenants`,
    { name },
    { 'X-Admin-Token': adminToken }
  );
  ensureStatus(res, [201], 'create tenant');
  const body = res.json();
  if (!body || !body.tenant_id) {
    throw new Error(`create tenant failed: missing tenant_id - ${res.body}`);
  }
  return body.tenant_id;
}

function createClient(tenantID, name, redirectURI, scopes, adminToken) {
  const res = postJSON(
    `${BASE_URL}/admin/clients`,
    {
      tenant_id: tenantID,
      name,
      redirect_uris: [redirectURI],
      allowed_grants: ['authorization_code', 'refresh_token'],
      allowed_scopes: scopes,
      public_client: true,
    },
    { 'X-Admin-Token': adminToken }
  );
  ensureStatus(res, [201], 'create client');
  const body = res.json();
  if (!body || !body.client_id) {
    throw new Error(`create client failed: missing client_id - ${res.body}`);
  }
  return body.client_id;
}

function authorizeUser(email, clientID, redirectURI, scopes) {
  const res = postJSON(`${BASE_URL}/auth/authorize`, {
    email,
    client_id: clientID,
    redirect_uri: redirectURI,
    scopes,
  });
  ensureStatus(res, [200], 'authorize');
  const body = res.json();
  if (!body || !body.code) {
    throw new Error(`authorize failed: missing code - ${res.body}`);
  }
  return body.code;
}

function exchangeCode(code, clientID, redirectURI) {
  const res = postJSON(`${BASE_URL}/auth/token`, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectURI,
    client_id: clientID,
  });
  ensureStatus(res, [200], 'token exchange');
  const body = res.json();
  if (!body || !body.access_token || !body.refresh_token) {
    throw new Error(`token exchange failed: missing tokens - ${res.body}`);
  }
  return body;
}

function postJSON(url, payload, extraHeaders) {
  const params = {
    headers: {
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
  };
  return http.post(url, JSON.stringify(payload), params);
}

function ensureStatus(res, allowed, label) {
  if (!allowed.includes(res.status)) {
    throw new Error(`${label} failed: ${res.status} - ${res.body}`);
  }
}

function parseScopes(raw) {
  if (!raw) {
    return [];
  }
  return raw
    .split(',')
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0);
}

function parsePositiveInt(value, defaultValue) {
  const parsed = parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return defaultValue;
  }
  return parsed;
}

// Scenario 1: Token Refresh Storm
// Purpose: Validate mutex contention under concurrent token refresh load
export function tokenRefreshScenario(data) {
  // Each VU gets its own dedicated token (VU IDs are 1-based)
  // This avoids refresh token contention since tokens are single-use
  const tokenIndex = (__VU - 1) % data.tokens.length;
  const token = data.tokens[tokenIndex];
  const clientID = data.clientID || CLIENT_ID;

  const payload = {
    grant_type: 'refresh_token',
    refresh_token: token.refreshToken,
    client_id: clientID,
  };

  const params = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'token_refresh' },
  };

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/auth/token`,
    JSON.stringify(payload),
    params
  );
  const duration = Date.now() - startTime;

  tokenRefreshLatency.add(duration);

  const success = check(res, {
    'token refresh status is 200': (r) => r.status === 200,
    'token refresh has access_token': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.access_token !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    tokenErrors.add(1);
    errorRate.add(1);
    console.log(`Token refresh failed: ${res.status} - ${res.body}`);
  } else {
    errorRate.add(0);
    // Update token for next iteration if successful
    try {
      const body = JSON.parse(res.body);
      if (body.refresh_token) {
        data.tokens[tokenIndex].refreshToken = body.refresh_token;
      }
      if (body.access_token) {
        data.tokens[tokenIndex].accessToken = body.access_token;
      }
    } catch {
      // Ignore parse errors
    }
  }
}

// Scenario 2: Consent Grant Burst
// Purpose: Validate consent service throughput with multi-purpose grants
export function consentBurstScenario(data) {
  // Each VU gets its own dedicated token (VU IDs are 1-based)
  const userIndex = (__VU - 1) % data.users.length;

  // Grant multiple purposes in one request
  const selectedPurposes = CONSENT_PURPOSES.slice(
    0,
    Math.floor(Math.random() * CONSENT_PURPOSES.length) + 1
  );

  const payload = {
    purposes: selectedPurposes,
  };

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${data.tokens[userIndex].accessToken}`,
    },
    tags: { name: 'consent_grant' },
  };

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/auth/consent`,
    JSON.stringify(payload),
    params
  );
  const duration = Date.now() - startTime;

  consentGrantLatency.add(duration);

  const success = check(res, {
    'consent grant status is 200 or 201': (r) => r.status === 200 || r.status === 201,
  });

  if (!success) {
    consentErrors.add(1);
    errorRate.add(1);
    if (res.status !== 401) { // Ignore auth errors in test mode
      console.log(`Consent grant failed: ${res.status} - ${res.body}`);
    }
  } else {
    errorRate.add(0);
  }

  sleep(0.1); // Small delay between requests
}

// Scenario 3: Mixed Load
// Purpose: Validate read performance during write contention
export function mixedLoadScenario(data) {
  // Each VU gets its own dedicated token (VU IDs are 1-based)
  const userIndex = (__VU - 1) % data.users.length;
  const token = data.tokens[userIndex];
  const clientID = data.clientID || CLIENT_ID;

  group('mixed_operations', () => {
    // 70% reads (session listing), 30% writes (token refresh)
    if (Math.random() < 0.7) {
      // Read operation: List sessions
      const params = {
        headers: {
          'Authorization': `Bearer ${token.accessToken}`,
        },
        tags: { name: 'session_list' },
      };

      const startTime = Date.now();
      const res = http.get(`${BASE_URL}/auth/sessions`, params);
      const duration = Date.now() - startTime;

      sessionListLatency.add(duration);

      check(res, {
        'session list status is 200': (r) => r.status === 200,
      });
    } else {
      // Write operation: Token refresh
      const payload = {
        grant_type: 'refresh_token',
        refresh_token: token.refreshToken,
        client_id: clientID,
      };

      const params = {
        headers: {
          'Content-Type': 'application/json',
        },
        tags: { name: 'token_refresh' },
      };

      const startTime = Date.now();
      const res = http.post(
        `${BASE_URL}/auth/token`,
        JSON.stringify(payload),
        params
      );
      const duration = Date.now() - startTime;

      tokenRefreshLatency.add(duration);

      const success = check(res, {
        'token refresh status is 200': (r) => r.status === 200,
      });

      if (success) {
        try {
          const body = JSON.parse(res.body);
          if (body.refresh_token) {
            data.tokens[userIndex].refreshToken = body.refresh_token;
          }
          if (body.access_token) {
            data.tokens[userIndex].accessToken = body.access_token;
          }
        } catch {
          // Ignore
        }
      }
    }
  });

  sleep(0.05); // 50ms between operations
}

// Scenario 4: OAuth Flow Storm
// Purpose: Test the full authorize → token exchange path under concurrent load.
// This exercises sharded transactions in authorize.go and token_exchange.go,
// plus JWT generation outside transaction boundaries.
export function oauthFlowScenario(data) {
  const clientID = data.clientID || CLIENT_ID;
  // Generate unique email per iteration to avoid user conflicts
  const uniqueEmail = `loadtest+oauth_${__VU}_${__ITER}@example.com`;

  const flowStart = Date.now();

  // Step 1: Authorize (creates user + session + auth code)
  const authorizeStart = Date.now();
  const authorizeRes = http.post(
    `${BASE_URL}/auth/authorize`,
    JSON.stringify({
      email: uniqueEmail,
      client_id: clientID,
      redirect_uri: REDIRECT_URI,
      scopes: DEFAULT_SCOPES,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'authorize' },
    }
  );
  authorizeLatency.add(Date.now() - authorizeStart);

  const authorizeOk = check(authorizeRes, {
    'authorize status is 200': (r) => r.status === 200,
    'authorize has code': (r) => {
      try {
        return JSON.parse(r.body).code !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!authorizeOk) {
    oauthFlowErrors.add(1);
    errorRate.add(1);
    console.log(`OAuth authorize failed: ${authorizeRes.status} - ${authorizeRes.body}`);
    return;
  }

  const authCode = JSON.parse(authorizeRes.body).code;

  // Step 2: Token exchange (creates tokens, advances session)
  const exchangeStart = Date.now();
  const tokenRes = http.post(
    `${BASE_URL}/auth/token`,
    JSON.stringify({
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: REDIRECT_URI,
      client_id: clientID,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'token_exchange' },
    }
  );
  tokenExchangeLatency.add(Date.now() - exchangeStart);

  const exchangeOk = check(tokenRes, {
    'token exchange status is 200': (r) => r.status === 200,
    'token exchange has access_token': (r) => {
      try {
        return JSON.parse(r.body).access_token !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!exchangeOk) {
    oauthFlowErrors.add(1);
    errorRate.add(1);
    console.log(`OAuth token exchange failed: ${tokenRes.status} - ${tokenRes.body}`);
    return;
  }

  // Full flow succeeded
  oauthFlowLatency.add(Date.now() - flowStart);
  errorRate.add(0);
}

// Teardown: Cleanup test data
export function teardown(data) {
  console.log('Load test complete');
  console.log(`Total tokens tested: ${data.tokens.length}`);
}

// Default function (required by k6)
export default function (data) {
  // This runs when no specific scenario is selected
  tokenRefreshScenario(data);
}
