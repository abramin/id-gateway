// k6 Load Test Suite for Credo OAuth Server
//
// Usage: k6 run loadtest/k6-credo.js
//        k6 run loadtest/k6-credo.js -e SCENARIO=resolve_client_burst
//
// IMPORTANT: Run the server with rate limiting disabled for load tests:
//   DISABLE_RATE_LIMITING=true docker compose up
//
// The script is self-bootstrapping in local/dev environments - no config needed.
// It automatically creates a tenant, client, and test users on each run.
//
// Environment variables (all optional):
//   BASE_URL                 - Server URL (default: http://localhost:8080)
//   ADMIN_TOKEN              - Admin API token (default: demo-admin-token)
//   CLIENT_ID                - Use existing client (skips tenant/client creation)
//   TENANT_ID                - Use existing tenant for client creation
//   REDIRECT_URI             - Redirect URI (default: http://localhost:3000/demo/callback.html)
//   SCOPES                   - Comma-separated scopes (default: openid,profile)
//   USER_COUNT               - Number of test users (default: 200)
//   BURST_CLIENT_COUNT       - Clients for ResolveClient burst (default: 100)
//   LARGE_TENANT_CLIENT_COUNT - Clients per large tenant (default: 500)
//   SCENARIO                 - Which scenario to run:
//
// Available scenarios:
//   token_refresh_storm      - Mutex contention under concurrent token refresh
//   consent_burst            - Consent service throughput with multi-purpose grants
//   mixed_load               - Read/write contention (sessions + token refresh)
//   oauth_flow_storm         - Full authorize → token exchange path
//   resolve_client_burst     - 1000 concurrent ResolveClient calls against 100 clients
//   client_onboarding_spike  - 50 concurrent CreateClient (bcrypt contention)
//   tenant_dashboard_load    - 100 concurrent GetTenant (tenants with 500+ clients)
//   rate_limit_sustained     - Rate limiting under sustained high request rate
//   rate_limit_cardinality   - Memory behavior under many unique IPs
//   all                      - Run all scenarios (default)

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
const resolveClientLatency = new Trend('resolve_client_latency', true);
const createClientLatency = new Trend('create_client_latency', true);
const getTenantLatency = new Trend('get_tenant_latency', true);
const rateLimitLatency = new Trend('rate_limit_latency', true);
const tokenErrors = new Counter('token_errors');
const consentErrors = new Counter('consent_errors');
const oauthFlowErrors = new Counter('oauth_flow_errors');
const resolveClientErrors = new Counter('resolve_client_errors');
const createClientErrors = new Counter('create_client_errors');
const getTenantErrors = new Counter('get_tenant_errors');
const rateLimited = new Counter('rate_limited_count');
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

    // Scenario 5: OAuth Burst (ResolveClient)
    // Tests 1000 concurrent ResolveClient calls against 100 clients.
    // Measures p95 latency and validates client resolution cache effectiveness.
    resolve_client_burst: {
      executor: 'constant-arrival-rate',
      rate: 200,                    // 200 req/sec targeting 1000 concurrent
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 100,
      maxVUs: 1000,
      exec: 'resolveClientBurstScenario',
      startTime: '0s',
      tags: { scenario: 'resolve_client_burst' },
    },

    // Scenario 6: Client Onboarding Spike
    // Tests 50 concurrent CreateClient requests to measure bcrypt contention.
    client_onboarding_spike: {
      executor: 'constant-vus',
      vus: 50,
      duration: '2m',
      exec: 'clientOnboardingScenario',
      startTime: '0s',
      tags: { scenario: 'client_onboarding' },
    },

    // Scenario 7: Tenant Dashboard Under Load
    // Tests 100 concurrent GetTenant calls for tenants with 500+ clients.
    // Measures N+1 query impact on p95 latency.
    tenant_dashboard_load: {
      executor: 'constant-vus',
      vus: 100,
      duration: '2m',
      exec: 'tenantDashboardScenario',
      startTime: '0s',
      tags: { scenario: 'tenant_dashboard' },
    },

    // Scenario 8: Rate Limit Sustained
    // Tests rate limiting behavior under sustained high request rate from single IP.
    rate_limit_sustained: {
      executor: 'constant-arrival-rate',
      rate: 500,                    // 500 req/sec to trigger rate limits
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'rateLimitSustainedScenario',
      startTime: '0s',
      tags: { scenario: 'rate_limit_sustained' },
    },

    // Scenario 9: Rate Limit High Cardinality
    // Tests memory behavior under many unique IPs via X-Forwarded-For.
    rate_limit_cardinality: {
      executor: 'per-vu-iterations',
      vus: 50,
      iterations: 100,              // Each VU simulates 100 unique IPs
      exec: 'rateLimitCardinalityScenario',
      startTime: '0s',
      tags: { scenario: 'rate_limit_cardinality' },
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

    // ResolveClient burst: p95 < 100ms (cache justification baseline)
    'resolve_client_latency{scenario:resolve_client_burst}': ['p(95)<100'],

    // Client onboarding: p95 < 500ms (bcrypt ~100ms per hash)
    'create_client_latency{scenario:client_onboarding}': ['p(95)<500'],

    // Tenant dashboard: p95 < 100ms (COUNT queries should be O(1))
    'get_tenant_latency{scenario:tenant_dashboard}': ['p(95)<100'],

    // Rate limiting: no latency thresholds (429s are expected behavior)
  },
};

// Filter scenarios based on SCENARIO env var
if (SCENARIO !== 'all') {
  const selectedScenario = options.scenarios[SCENARIO];
  if (selectedScenario) {
    options.scenarios = { [SCENARIO]: selectedScenario };
  }
}

// Configuration for new scenarios
const BURST_CLIENT_COUNT = parsePositiveInt(__ENV.BURST_CLIENT_COUNT, 100);
const LARGE_TENANT_CLIENT_COUNT = parsePositiveInt(__ENV.LARGE_TENANT_CLIENT_COUNT, 500);

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

  // Determine which setup data is needed based on scenario
  const scenariosNeedingTokens = [
    'all', 'token_refresh_storm', 'consent_burst', 'mixed_load', 'oauth_flow_storm'
  ];
  const needsTokens = scenariosNeedingTokens.includes(SCENARIO);
  const needsBurstClients = SCENARIO === 'all' || SCENARIO === 'resolve_client_burst';
  const needsOnboardingTenant = SCENARIO === 'all' || SCENARIO === 'client_onboarding_spike';
  const needsLargeTenants = SCENARIO === 'all' || SCENARIO === 'tenant_dashboard_load';

  // Create users/tokens only if needed (token refresh, consent, mixed load, oauth flow)
  const tokens = [];
  const users = [];
  if (needsTokens) {
    console.log(`Creating ${USER_COUNT} test users...`);
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
    console.log(`Created ${tokens.length} test users`);
  }

  // Setup for new scenarios
  let burstClients = [];
  let onboardingTenantID = '';
  let largeTenants = [];

  // Create 100 clients for ResolveClient burst scenario
  if (needsBurstClients) {
    console.log(`Creating ${BURST_CLIENT_COUNT} clients for ResolveClient burst...`);
    for (let i = 0; i < BURST_CLIENT_COUNT; i++) {
      const burstClientID = createClient(
        tenantID,
        `burst-client-${i}-${Date.now()}`,
        REDIRECT_URI,
        DEFAULT_SCOPES,
        ADMIN_TOKEN
      );
      burstClients.push(burstClientID);
    }
    console.log(`Created ${burstClients.length} burst clients`);
  }

  // Create a dedicated tenant for client onboarding spike
  if (needsOnboardingTenant) {
    console.log('Creating tenant for client onboarding spike...');
    onboardingTenantID = createTenant(`onboarding-tenant-${Date.now()}`, ADMIN_TOKEN);
    console.log(`Created onboarding tenant: ${onboardingTenantID}`);
  }

  // Create tenants with 500+ clients for tenant dashboard load
  if (needsLargeTenants) {
    console.log(`Creating tenant with ${LARGE_TENANT_CLIENT_COUNT} clients for dashboard load...`);
    const largeTenantID = createTenant(`large-tenant-${Date.now()}`, ADMIN_TOKEN);
    for (let i = 0; i < LARGE_TENANT_CLIENT_COUNT; i++) {
      createClient(
        largeTenantID,
        `large-client-${i}`,
        REDIRECT_URI,
        DEFAULT_SCOPES,
        ADMIN_TOKEN
      );
      if ((i + 1) % 100 === 0) {
        console.log(`  Created ${i + 1}/${LARGE_TENANT_CLIENT_COUNT} clients...`);
      }
    }
    largeTenants.push(largeTenantID);
    console.log(`Created large tenant with ${LARGE_TENANT_CLIENT_COUNT} clients`);
  }

  return {
    tokens,
    users,
    clientID,
    tenantID,
    burstClients,
    onboardingTenantID,
    largeTenants,
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

// Scenario 5: ResolveClient Burst
// Purpose: Validate ResolveClient performance under 1000 concurrent calls against 100 clients
export function resolveClientBurstScenario(data) {
  // Pick a random client from the burst clients pool
  const clients = data.burstClients || [data.clientID];
  const clientID = clients[Math.floor(Math.random() * clients.length)];
  const uniqueEmail = `loadtest+burst_${__VU}_${__ITER}@example.com`;

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/auth/authorize`,
    JSON.stringify({
      email: uniqueEmail,
      client_id: clientID,
      redirect_uri: REDIRECT_URI,
      scopes: DEFAULT_SCOPES,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'resolve_client' },
    }
  );
  const duration = Date.now() - startTime;

  resolveClientLatency.add(duration);

  const success = check(res, {
    'resolve client status is 200': (r) => r.status === 200,
    'resolve client has code': (r) => {
      try {
        return JSON.parse(r.body).code !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    resolveClientErrors.add(1);
    errorRate.add(1);
    if (res.status !== 429) {
      console.log(`ResolveClient failed: ${res.status} - ${res.body}`);
    }
  } else {
    errorRate.add(0);
  }
}

// Scenario 6: Client Onboarding Spike
// Purpose: Validate bcrypt contention under 50 concurrent CreateClient requests
export function clientOnboardingScenario(data) {
  // Use the tenant created for onboarding tests
  const tenantID = data.onboardingTenantID || data.tenantID;
  const clientName = `loadtest-client-${__VU}-${__ITER}-${Date.now()}`;

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/admin/clients`,
    JSON.stringify({
      tenant_id: tenantID,
      name: clientName,
      redirect_uris: [REDIRECT_URI],
      allowed_grants: ['authorization_code', 'refresh_token'],
      allowed_scopes: DEFAULT_SCOPES,
      public_client: true,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Admin-Token': ADMIN_TOKEN,
      },
      tags: { name: 'create_client' },
    }
  );
  const duration = Date.now() - startTime;

  createClientLatency.add(duration);

  const success = check(res, {
    'create client status is 201': (r) => r.status === 201,
    'create client has client_id': (r) => {
      try {
        return JSON.parse(r.body).client_id !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    createClientErrors.add(1);
    errorRate.add(1);
    console.log(`CreateClient failed: ${res.status} - ${res.body}`);
  } else {
    errorRate.add(0);
  }

  sleep(0.1); // Small delay to avoid overwhelming the server
}

// Scenario 7: Tenant Dashboard Under Load
// Purpose: Validate GetTenant performance for tenants with 500+ clients (N+1 impact)
export function tenantDashboardScenario(data) {
  // Use the tenant with many clients
  const tenants = data.largeTenants || [data.tenantID];
  const tenantID = tenants[Math.floor(Math.random() * tenants.length)];

  const startTime = Date.now();
  const res = http.get(
    `${BASE_URL}/admin/tenants/${tenantID}`,
    {
      headers: {
        'X-Admin-Token': ADMIN_TOKEN,
      },
      tags: { name: 'get_tenant' },
    }
  );
  const duration = Date.now() - startTime;

  getTenantLatency.add(duration);

  const success = check(res, {
    'get tenant status is 200': (r) => r.status === 200,
    'get tenant has client_count': (r) => {
      try {
        return JSON.parse(r.body).client_count !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    getTenantErrors.add(1);
    errorRate.add(1);
    console.log(`GetTenant failed: ${res.status} - ${res.body}`);
  } else {
    errorRate.add(0);
  }

  sleep(0.05); // 50ms between operations
}

// Scenario 8: Rate Limit Sustained
// Purpose: Validate rate limiting behavior under sustained high request rate from single IP
export function rateLimitSustainedScenario() {
  const startTime = Date.now();
  const res = http.get(`${BASE_URL}/health`, {
    tags: { name: 'rate_limit_health' },
  });
  const duration = Date.now() - startTime;

  rateLimitLatency.add(duration);

  if (res.status === 429) {
    rateLimited.add(1);
    // 429 is expected behavior, not an error
  }

  check(res, {
    'rate limit response is 200 or 429': (r) => r.status === 200 || r.status === 429,
  });
}

// Scenario 9: Rate Limit High Cardinality
// Purpose: Validate memory behavior under many unique IPs via X-Forwarded-For
export function rateLimitCardinalityScenario() {
  // Generate unique IP per VU+iteration
  const ipCounter = __VU * 10000 + __ITER;
  const ip = `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}`;

  const startTime = Date.now();
  const res = http.get(`${BASE_URL}/health`, {
    headers: {
      'X-Forwarded-For': ip,
    },
    tags: { name: 'rate_limit_cardinality' },
  });
  const duration = Date.now() - startTime;

  rateLimitLatency.add(duration);

  if (res.status === 429) {
    rateLimited.add(1);
  }

  check(res, {
    'cardinality response is 200 or 429': (r) => r.status === 200 || r.status === 429,
  });
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
