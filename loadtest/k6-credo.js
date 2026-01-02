// k6 Load Test Suite for Credo OAuth Server
//
// Usage: k6 run loadtest/k6-credo.js
//        k6 run loadtest/k6-credo.js -e SCENARIO=resolve_client_burst
//        k6 run loadtest/k6-credo.js -e QUICK=true              # Halves all durations
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
//   QUICK                    - Set to 'true' to halve all durations (~38 min vs ~76 min)
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
//   global_throttle_spike    - [PERF] Spike test: 1000→10000 RPS to stress global throttle row locks
//   hot_key_contention       - [PERF] Hot key test: 80% traffic to 10 IPs for advisory lock contention
//   auth_lockout_race        - [PERF] Concurrent auth failures to expose TOCTOU races in lockout
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

// Performance test metrics
const globalThrottleLatency = new Trend('global_throttle_latency', true);
const hotKeyLatency = new Trend('hot_key_latency', true);
const authLockoutLatency = new Trend('auth_lockout_latency', true);
const authLockoutRaceDetected = new Counter('auth_lockout_race_detected');

// Decision module metrics
const decisionEvaluateLatency = new Trend('decision_evaluate_latency', true);
const decisionAgeVerifyLatency = new Trend('decision_age_verify_latency', true);
const decisionSanctionsLatency = new Trend('decision_sanctions_latency', true);
const decisionErrors = new Counter('decision_errors');

// Evidence module metrics
const evidenceCitizenLatency = new Trend('evidence_citizen_latency', true);
const evidenceSanctionsLatency = new Trend('evidence_sanctions_latency', true);
const evidenceVCIssueLatency = new Trend('evidence_vc_issue_latency', true);
const evidenceCheckLatency = new Trend('evidence_check_latency', true);
const evidenceErrors = new Counter('evidence_errors');
const evidenceCacheHits = new Counter('evidence_cache_hits');
const evidenceCacheMisses = new Counter('evidence_cache_misses');

// Auth additional metrics
const authCodeReplayLatency = new Trend('auth_code_replay_latency', true);
const authCodeReplayErrors = new Counter('auth_code_replay_errors');
const trlWriteLatency = new Trend('trl_write_latency', true);
const userinfoLatency = new Trend('userinfo_latency', true);

// Consent additional metrics
const consentRevokeLatency = new Trend('consent_revoke_latency', true);
const consentDeleteLatency = new Trend('consent_delete_latency', true);
const consentAdminRevokeLatency = new Trend('consent_admin_revoke_latency', true);

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

// Quick mode: halves all durations for faster test runs (~38 min instead of ~76 min)
const QUICK_MODE = __ENV.QUICK === 'true' || __ENV.QUICK === '1';
const TIME_MULTIPLIER = QUICK_MODE ? 0.5 : 1.0;

// Duration helper - applies time multiplier and formats as k6 duration string
function dur(minutes, seconds = 0) {
  const totalSeconds = Math.round((minutes * 60 + seconds) * TIME_MULTIPLIER);
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  if (m === 0) return `${s}s`;
  if (s === 0) return `${m}m`;
  return `${m}m${s}s`;
}

// Start time helper - calculates cumulative start time with buffer
function startAt(minutes, seconds = 0) {
  const totalSeconds = Math.round((minutes * 60 + seconds) * TIME_MULTIPLIER);
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  if (m === 0) return `${s}s`;
  if (s === 0) return `${m}m`;
  return `${m}m${s}s`;
}

const CONSENT_PURPOSES = ['login', 'registry_check', 'vc_issuance', 'decision_evaluation'];

// Log QUICK mode status at module load time
if (QUICK_MODE) {
  console.log('QUICK MODE ENABLED: All durations halved (~38 min total)');
} else {
  console.log('NORMAL MODE: Full durations (~76 min total). Use QUICK=true for faster runs.');
}

// Scenario configurations
export const options = {
  scenarios: {
    // ========== AUTH MODULE SCENARIOS ==========
    // Scenarios run SEQUENTIALLY when SCENARIO=all (staggered startTime)
    // Total estimated runtime: ~76 min (normal) or ~38 min (QUICK=true)

    // Scenario 1: Token Refresh Storm (5m)
    // Tests mutex contention under concurrent token refresh load
    token_refresh_storm: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: dur(5),
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'tokenRefreshScenario',
      startTime: startAt(0),
      tags: { scenario: 'token_refresh' },
    },

    // Scenario 2: Consent Grant Burst (5m)
    // Tests consent service throughput with multi-purpose grants
    consent_burst: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 100,
      stages: [
        { duration: dur(1), target: 50 },
        { duration: dur(3), target: 50 },
        { duration: dur(1), target: 0 },
      ],
      exec: 'consentBurstScenario',
      startTime: startAt(5, 10),
      tags: { scenario: 'consent_burst' },
    },

    // Scenario 3: Mixed Load (5m)
    // Tests read performance during write contention
    mixed_load: {
      executor: 'constant-vus',
      vus: 50,
      duration: dur(5),
      exec: 'mixedLoadScenario',
      startTime: startAt(10, 20),
      tags: { scenario: 'mixed_load' },
    },

    // Scenario 4: OAuth Flow Storm (5m)
    // Full authorize → token exchange path
    oauth_flow_storm: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: dur(5),
      preAllocatedVUs: 50,
      maxVUs: 150,
      exec: 'oauthFlowScenario',
      startTime: startAt(15, 30),
      tags: { scenario: 'oauth_flow' },
    },

    // Scenario 5: ResolveClient Burst (1m)
    // 1000 concurrent ResolveClient calls against 100 clients
    resolve_client_burst: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: dur(1),
      preAllocatedVUs: 100,
      maxVUs: 1000,
      exec: 'resolveClientBurstScenario',
      startTime: startAt(20, 40),
      tags: { scenario: 'resolve_client_burst' },
    },

    // Scenario 6: Client Onboarding Spike (2m)
    // 50 concurrent CreateClient (bcrypt contention)
    client_onboarding_spike: {
      executor: 'constant-vus',
      vus: 50,
      duration: dur(2),
      exec: 'clientOnboardingScenario',
      startTime: startAt(21, 50),
      tags: { scenario: 'client_onboarding' },
    },

    // Scenario 7: Tenant Dashboard Load (2m)
    // 100 concurrent GetTenant for tenants with 500+ clients
    tenant_dashboard_load: {
      executor: 'constant-vus',
      vus: 100,
      duration: dur(2),
      exec: 'tenantDashboardScenario',
      startTime: startAt(24),
      tags: { scenario: 'tenant_dashboard' },
    },

    // Scenario 8: Rate Limit Sustained (1m)
    // Rate limiting under sustained high request rate
    rate_limit_sustained: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: dur(1),
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'rateLimitSustainedScenario',
      startTime: startAt(26, 10),
      tags: { scenario: 'rate_limit_sustained' },
    },

    // Scenario 9: Rate Limit Cardinality (~2m)
    // Memory behavior under many unique IPs
    rate_limit_cardinality: {
      executor: 'per-vu-iterations',
      vus: 50,
      iterations: 100,
      exec: 'rateLimitCardinalityScenario',
      startTime: startAt(27, 20),
      tags: { scenario: 'rate_limit_cardinality' },
    },

    // Scenario 10: Consent Shard Contention (1m)
    // Single-user hot path stress test
    consent_shard_contention: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: dur(1),
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'consentShardContentionScenario',
      startTime: startAt(29, 30),
      tags: { scenario: 'consent_shard_contention' },
    },

    // Scenario 11: Consent List Load (2m)
    // Listing consents for users with many purposes
    consent_list_load: {
      executor: 'constant-vus',
      vus: 50,
      duration: dur(2),
      exec: 'consentListScenario',
      startTime: startAt(30, 40),
      tags: { scenario: 'consent_list_load' },
    },

    // ========== PERFORMANCE BOTTLENECK TESTS ==========

    // Scenario 12: Global Throttle Spike (1m)
    // Stress global throttle PostgreSQL row locks
    global_throttle_spike: {
      executor: 'ramping-arrival-rate',
      startRate: 1000,
      timeUnit: '1s',
      preAllocatedVUs: 200,
      maxVUs: 2000,
      stages: [
        { duration: dur(0, 10), target: 10000 },
        { duration: dur(0, 30), target: 10000 },
        { duration: dur(0, 10), target: 1000 },
      ],
      exec: 'globalThrottleSpikeScenario',
      startTime: startAt(32, 50),
      tags: { scenario: 'global_throttle_spike' },
    },

    // Scenario 13: Hot Key Contention (2m)
    // 80% traffic to 10 hot IPs
    hot_key_contention: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: dur(2),
      preAllocatedVUs: 100,
      maxVUs: 500,
      exec: 'hotKeyContentionScenario',
      startTime: startAt(33, 50),
      tags: { scenario: 'hot_key_contention' },
    },

    // Scenario 14: Auth Lockout Race (~1m)
    // Concurrent login failures for TOCTOU detection
    auth_lockout_race: {
      executor: 'per-vu-iterations',
      vus: 100,
      iterations: 15,
      exec: 'authLockoutRaceScenario',
      startTime: startAt(36),
      tags: { scenario: 'auth_lockout_race' },
    },

    // ========== DECISION MODULE SCENARIOS ==========

    // Scenario 15: Decision Age Verification (5m)
    decision_age_verify: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: dur(1), target: 500 },
        { duration: dur(3), target: 500 },
        { duration: dur(1), target: 100 },
      ],
      exec: 'decisionAgeVerifyScenario',
      startTime: startAt(37, 10),
      tags: { scenario: 'decision_age_verify' },
    },

    // Scenario 16: Decision Sanctions Screening (5m)
    decision_sanctions: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: dur(1), target: 800 },
        { duration: dur(3), target: 800 },
        { duration: dur(1), target: 100 },
      ],
      exec: 'decisionSanctionsScenario',
      startTime: startAt(42, 20),
      tags: { scenario: 'decision_sanctions' },
    },

    // Scenario 17: Decision Same User (2m)
    decision_same_user: {
      executor: 'constant-vus',
      vus: 50,
      duration: dur(2),
      exec: 'decisionSameUserScenario',
      startTime: startAt(47, 30),
      tags: { scenario: 'decision_same_user' },
    },

    // Scenario 18: Decision Cache Hit (2m)
    decision_cache_hit: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: dur(2),
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'decisionCacheHitScenario',
      startTime: startAt(49, 40),
      tags: { scenario: 'decision_cache_hit' },
    },

    // Scenario 19: Decision Rule Paths (3m)
    decision_rule_paths: {
      executor: 'constant-vus',
      vus: 100,
      duration: dur(3),
      exec: 'decisionRulePathsScenario',
      startTime: startAt(51, 50),
      tags: { scenario: 'decision_rule_paths' },
    },

    // Scenario 20: Decision Consent Denial (2m)
    decision_consent_denial: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: dur(2),
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'decisionConsentDenialScenario',
      startTime: startAt(55),
      tags: { scenario: 'decision_consent_denial' },
    },

    // ========== EVIDENCE MODULE SCENARIOS ==========

    // Scenario 21: Evidence Citizen (4m)
    evidence_citizen: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: dur(1), target: 500 },
        { duration: dur(2), target: 500 },
        { duration: dur(1), target: 100 },
      ],
      exec: 'evidenceCitizenScenario',
      startTime: startAt(57, 10),
      tags: { scenario: 'evidence_citizen' },
    },

    // Scenario 22: Evidence Sanctions (4m)
    evidence_sanctions: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: dur(1), target: 500 },
        { duration: dur(2), target: 500 },
        { duration: dur(1), target: 100 },
      ],
      exec: 'evidenceSanctionsScenario',
      startTime: startAt(61, 20),
      tags: { scenario: 'evidence_sanctions' },
    },

    // Scenario 23: Evidence VC Issuance (2m)
    evidence_vc_issue: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: dur(2),
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'evidenceVCIssueScenario',
      startTime: startAt(65, 30),
      tags: { scenario: 'evidence_vc_issue' },
    },

    // Scenario 24: Evidence Cache Stampede (30s)
    evidence_cache_stampede: {
      executor: 'shared-iterations',
      vus: 100,
      iterations: 1000,
      maxDuration: dur(0, 30),
      exec: 'evidenceCacheStampedeScenario',
      startTime: startAt(67, 40),
      tags: { scenario: 'evidence_cache_stampede' },
    },

    // Scenario 25: Evidence Check (3m)
    evidence_check: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: dur(3),
      preAllocatedVUs: 50,
      maxVUs: 300,
      exec: 'evidenceCheckScenario',
      startTime: startAt(68, 20),
      tags: { scenario: 'evidence_check' },
    },

    // ========== ADDITIONAL AUTH SCENARIOS ==========

    // Scenario 26: Auth Code Replay (~30s)
    auth_code_replay: {
      executor: 'per-vu-iterations',
      vus: 50,
      iterations: 3,
      exec: 'authCodeReplayScenario',
      startTime: startAt(71, 30),
      tags: { scenario: 'auth_code_replay' },
    },

    // Scenario 27: TRL Write Saturation (1m)
    trl_write_saturation: {
      executor: 'constant-arrival-rate',
      rate: 500,
      timeUnit: '1s',
      duration: dur(1),
      preAllocatedVUs: 100,
      maxVUs: 500,
      exec: 'trlWriteSaturationScenario',
      startTime: startAt(72, 10),
      tags: { scenario: 'trl_write_saturation' },
    },

    // Scenario 28: Userinfo Throughput (30s)
    userinfo_throughput: {
      executor: 'constant-arrival-rate',
      rate: 2000,
      timeUnit: '1s',
      duration: dur(0, 30),
      preAllocatedVUs: 100,
      maxVUs: 500,
      exec: 'userinfoThroughputScenario',
      startTime: startAt(73, 20),
      tags: { scenario: 'userinfo_throughput' },
    },

    // ========== ADDITIONAL CONSENT SCENARIOS ==========

    // Scenario 29: Consent Revoke/Grant Race (1m)
    consent_revoke_grant_race: {
      executor: 'constant-vus',
      vus: 50,
      duration: dur(1),
      exec: 'consentRevokeGrantRaceScenario',
      startTime: startAt(74),
      tags: { scenario: 'consent_revoke_grant_race' },
    },

    // Scenario 30: Consent GDPR Delete (~1m)
    consent_gdpr_delete: {
      executor: 'per-vu-iterations',
      vus: 50,
      iterations: 5,
      exec: 'consentGDPRDeleteScenario',
      startTime: startAt(75, 10),
      tags: { scenario: 'consent_gdpr_delete' },
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

    // Consent shard contention: validate lock wait time under single-user load
    'consent_grant_latency{scenario:consent_shard_contention}': ['p(95)<500'],

    // Consent list: validate O(n) list performance
    'consent_list_latency{scenario:consent_list_load}': ['p(95)<100'],

    // Performance bottleneck tests
    // Global throttle spike: expect degradation, track p99 for analysis
    'global_throttle_latency{scenario:global_throttle_spike}': ['p(99)<1000'],

    // Hot key contention: p95 should stay reasonable even under skewed load
    'hot_key_latency{scenario:hot_key_contention}': ['p(95)<500'],

    // Auth lockout race: no races should be detected (counter should stay at 0)
    'auth_lockout_race_detected{scenario:auth_lockout_race}': ['count<1'],

    // Decision module thresholds
    'decision_age_verify_latency{scenario:decision_age_verify}': ['p(95)<150'],
    'decision_sanctions_latency{scenario:decision_sanctions}': ['p(95)<100'],
    'decision_evaluate_latency{scenario:decision_same_user}': ['p(95)<200'],
    'decision_evaluate_latency{scenario:decision_cache_hit}': ['p(95)<100'],
    'decision_evaluate_latency{scenario:decision_rule_paths}': ['p(95)<200'],
    'decision_evaluate_latency{scenario:decision_consent_denial}': ['p(95)<50'],

    // Evidence module thresholds
    'evidence_citizen_latency{scenario:evidence_citizen}': ['p(95)<150'],
    'evidence_sanctions_latency{scenario:evidence_sanctions}': ['p(95)<150'],
    'evidence_vc_issue_latency{scenario:evidence_vc_issue}': ['p(95)<3000'],
    'evidence_check_latency{scenario:evidence_check}': ['p(95)<200'],
    'evidence_check_latency{scenario:evidence_cache_stampede}': ['p(95)<500'],

    // Additional auth thresholds
    'auth_code_replay_latency{scenario:auth_code_replay}': ['p(95)<100'],
    'trl_write_latency{scenario:trl_write_saturation}': ['p(95)<50'],
    'userinfo_latency{scenario:userinfo_throughput}': ['p(95)<50'],

    // Additional consent thresholds
    'consent_revoke_latency{scenario:consent_revoke_grant_race}': ['p(95)<200'],
    'consent_delete_latency{scenario:consent_gdpr_delete}': ['p(95)<300'],
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
    'all', 'token_refresh_storm', 'consent_burst', 'mixed_load', 'oauth_flow_storm',
    'consent_shard_contention', 'consent_list_load'
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

// Scenario 10: Consent Shard Contention
// Purpose: Stress test the sharded lock by hitting same user with many concurrent grants
export function consentShardContentionScenario(data) {
  // Use a single fixed user to maximize contention on one shard
  const userIndex = 0; // Always use first user for maximum contention
  const token = data.tokens[userIndex];

  // Rotate through purposes to simulate real usage
  const purposeIndex = __ITER % CONSENT_PURPOSES.length;
  const purpose = CONSENT_PURPOSES[purposeIndex];

  const payload = {
    purposes: [purpose],
  };

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token.accessToken}`,
    },
    tags: { name: 'consent_shard_contention' },
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
    'shard contention grant status is 200': (r) => r.status === 200,
  });

  if (!success) {
    consentErrors.add(1);
    errorRate.add(1);
    if (res.status !== 401 && res.status !== 429) {
      console.log(`Shard contention grant failed: ${res.status} - ${res.body}`);
    }
  } else {
    errorRate.add(0);
  }
}

// Custom metric for consent list latency
const consentListLatency = new Trend('consent_list_latency', true);

// Scenario 11: Consent List Performance
// Purpose: Validate O(n) list performance with users having multiple consents
export function consentListScenario(data) {
  const userIndex = (__VU - 1) % data.tokens.length;
  const token = data.tokens[userIndex];

  const params = {
    headers: {
      'Authorization': `Bearer ${token.accessToken}`,
    },
    tags: { name: 'consent_list' },
  };

  const startTime = Date.now();
  const res = http.get(`${BASE_URL}/auth/consent`, params);
  const duration = Date.now() - startTime;

  consentListLatency.add(duration);

  const success = check(res, {
    'consent list status is 200': (r) => r.status === 200,
    'consent list has consents array': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.consents);
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    errorRate.add(1);
    if (res.status !== 401) {
      console.log(`Consent list failed: ${res.status} - ${res.body}`);
    }
  } else {
    errorRate.add(0);
  }

  sleep(0.05); // 50ms between requests
}

// ========== PERFORMANCE BOTTLENECK TEST SCENARIOS ==========

// Scenario 12: Global Throttle Spike Test
// Purpose: Stress global throttle PostgreSQL row locks with rapid RPS spike.
// Validates FOR UPDATE contention on 2 shared rows (second + hour buckets).
export function globalThrottleSpikeScenario() {
  const startTime = Date.now();
  const res = http.get(`${BASE_URL}/health`, {
    tags: { name: 'global_throttle_spike' },
  });
  const duration = Date.now() - startTime;

  globalThrottleLatency.add(duration);

  // Track 429s but don't count them as errors (expected behavior under load)
  if (res.status === 429) {
    rateLimited.add(1);
  }

  check(res, {
    'global throttle response is 200 or 429 or 503': (r) =>
      r.status === 200 || r.status === 429 || r.status === 503,
  });
}

// Scenario 13: Hot Key Advisory Lock Contention
// Purpose: 80% traffic to 10 hot IPs to stress advisory lock wait times.
// Validates that sharded locks don't create excessive lock queues.
export function hotKeyContentionScenario() {
  // 80% of traffic goes to 10 hot IPs
  const hotIPs = [
    '192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5',
    '192.168.1.6', '192.168.1.7', '192.168.1.8', '192.168.1.9', '192.168.1.10',
  ];

  let ip;
  if (Math.random() < 0.8) {
    // 80% to hot IPs
    ip = hotIPs[Math.floor(Math.random() * hotIPs.length)];
  } else {
    // 20% to random IPs (cold keys)
    const ipNum = Math.floor(Math.random() * 1000000);
    ip = `10.${(ipNum >> 16) & 255}.${(ipNum >> 8) & 255}.${ipNum & 255}`;
  }

  const startTime = Date.now();
  const res = http.get(`${BASE_URL}/health`, {
    headers: {
      'X-Forwarded-For': ip,
    },
    tags: { name: 'hot_key_contention' },
  });
  const duration = Date.now() - startTime;

  hotKeyLatency.add(duration);

  if (res.status === 429) {
    rateLimited.add(1);
  }

  check(res, {
    'hot key response is 200 or 429': (r) => r.status === 200 || r.status === 429,
  });
}

// Scenario 14: Auth Lockout TOCTOU Race Detection
// Purpose: 100 concurrent login failures for same user to expose TOCTOU races.
// All VUs attack the same username:IP to maximize contention.
// Expected: failure_count should equal total attempts; hard lock at threshold 10.
export function authLockoutRaceScenario(data) {
  const clientID = data.clientID || CLIENT_ID;
  // All VUs use the same credentials to maximize contention
  const targetEmail = `toctou-race-test@example.com`;
  const targetIP = '203.0.113.42'; // Fixed IP for composite key

  const startTime = Date.now();
  // Attempt authorize which will trigger auth lockout check
  const res = http.post(
    `${BASE_URL}/auth/authorize`,
    JSON.stringify({
      email: targetEmail,
      client_id: clientID,
      redirect_uri: REDIRECT_URI,
      scopes: DEFAULT_SCOPES,
      // Include the fixed IP in request for composite key
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': targetIP,
      },
      tags: { name: 'auth_lockout_race' },
    }
  );
  const duration = Date.now() - startTime;

  authLockoutLatency.add(duration);

  // After 10 daily failures, user should be hard locked (429 expected)
  // After 5 window failures, user should be soft locked (429 expected)
  // Success (200) after 10+ failures indicates a TOCTOU race
  const isExpectedLockout = res.status === 429;
  const isSuccess = res.status === 200;
  const totalAttempts = __VU * __ITER;

  // If we're past the hard lock threshold (10 daily failures) and still getting 200s,
  // that's a potential race condition
  if (isSuccess && totalAttempts > 10) {
    // This could indicate a race - the failure count wasn't incremented atomically
    // Log for manual inspection; the threshold check will catch if too many races occur
    console.log(`Potential TOCTOU race: VU=${__VU} ITER=${__ITER} status=200 after ${totalAttempts} total attempts`);
    authLockoutRaceDetected.add(1);
  }

  check(res, {
    'auth lockout response is valid': (r) =>
      r.status === 200 || r.status === 400 || r.status === 429,
  });
}

// ========== DECISION MODULE SCENARIO IMPLEMENTATIONS ==========

// Test data for decision scenarios - national IDs for different profiles
const DECISION_TEST_PROFILES = {
  valid_adult: '19800101-1234',      // Valid citizen, over 18, not sanctioned
  valid_minor: '20100101-5678',      // Valid citizen, under 18, not sanctioned
  sanctioned: '19750501-9999',       // Sanctioned individual
  invalid_citizen: '00000000-0000',  // Invalid/unknown citizen
  with_credential: '19850315-4321',  // Has existing VC
};

// Scenario 15: Decision Age Verification Throughput
export function decisionAgeVerifyScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  const nationalID = DECISION_TEST_PROFILES.valid_adult;

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/decision/evaluate`,
    JSON.stringify({
      purpose: 'age_verification',
      national_id: nationalID,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'decision_age_verify' },
    }
  );
  const duration = Date.now() - startTime;

  decisionAgeVerifyLatency.add(duration);

  const success = check(res, {
    'decision age verify status is 200': (r) => r.status === 200,
    'decision has outcome': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.outcome !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    decisionErrors.add(1);
    errorRate.add(1);
    if (res.status !== 401 && res.status !== 403) {
      console.log(`Decision age verify failed: ${res.status} - ${res.body}`);
    }
  } else {
    errorRate.add(0);
  }
}

// Scenario 16: Decision Sanctions Screening Throughput
export function decisionSanctionsScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  const nationalID = DECISION_TEST_PROFILES.valid_adult;

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/decision/evaluate`,
    JSON.stringify({
      purpose: 'sanctions_screening',
      national_id: nationalID,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'decision_sanctions' },
    }
  );
  const duration = Date.now() - startTime;

  decisionSanctionsLatency.add(duration);

  const success = check(res, {
    'decision sanctions status is 200': (r) => r.status === 200,
  });

  if (!success) {
    decisionErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }
}

// Scenario 17: Decision Concurrent Same User
export function decisionSameUserScenario(data) {
  // All VUs use the same user to maximize contention
  const token = data.tokens[0];
  const nationalID = DECISION_TEST_PROFILES.valid_adult;

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/decision/evaluate`,
    JSON.stringify({
      purpose: 'age_verification',
      national_id: nationalID,
      request_id: `req-${__VU}-${__ITER}-${Date.now()}`,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'decision_same_user' },
    }
  );
  const duration = Date.now() - startTime;

  decisionEvaluateLatency.add(duration);

  const success = check(res, {
    'decision same user status is 200': (r) => r.status === 200,
  });

  if (!success) {
    decisionErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }

  sleep(0.05);
}

// Scenario 18: Decision Cache Hit Test
export function decisionCacheHitScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  // Use only 10 national IDs to maximize cache hits
  const nationalIDs = [
    '19800101-0001', '19800101-0002', '19800101-0003', '19800101-0004', '19800101-0005',
    '19800101-0006', '19800101-0007', '19800101-0008', '19800101-0009', '19800101-0010',
  ];
  const nationalID = nationalIDs[__ITER % nationalIDs.length];

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/decision/evaluate`,
    JSON.stringify({
      purpose: 'sanctions_screening',
      national_id: nationalID,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'decision_cache_hit' },
    }
  );
  const duration = Date.now() - startTime;

  decisionEvaluateLatency.add(duration);

  check(res, {
    'decision cache hit status is 200': (r) => r.status === 200,
  });
}

// Scenario 19: Decision All Rule Paths
export function decisionRulePathsScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  // Cycle through different profiles to hit all rule paths
  const profiles = Object.values(DECISION_TEST_PROFILES);
  const nationalID = profiles[__ITER % profiles.length];

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/decision/evaluate`,
    JSON.stringify({
      purpose: 'age_verification',
      national_id: nationalID,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'decision_rule_paths' },
    }
  );
  const duration = Date.now() - startTime;

  decisionEvaluateLatency.add(duration);

  // All responses are valid (pass, fail, or error responses)
  check(res, {
    'decision rule paths response valid': (r) => r.status === 200 || r.status === 400 || r.status === 403,
  });

  sleep(0.05);
}

// Scenario 20: Decision Consent Denial Fast-Fail
export function decisionConsentDenialScenario(data) {
  // Use users without consent to test fast-fail path
  const token = data.tokens[(__VU - 1) % data.tokens.length];

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/decision/evaluate`,
    JSON.stringify({
      purpose: 'age_verification',
      national_id: DECISION_TEST_PROFILES.valid_adult,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'decision_consent_denial' },
    }
  );
  const duration = Date.now() - startTime;

  decisionEvaluateLatency.add(duration);

  // Expect 403 for denied consent (fast path)
  check(res, {
    'decision consent denial is fast': (r) => r.status === 200 || r.status === 403,
  });
}

// ========== EVIDENCE MODULE SCENARIO IMPLEMENTATIONS ==========

// Scenario 21: Evidence Citizen Lookup Throughput
export function evidenceCitizenScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  const nationalID = `19800101-${String(__VU * 1000 + __ITER).padStart(4, '0')}`;

  const startTime = Date.now();
  const res = http.get(
    `${BASE_URL}/evidence/citizen/${nationalID}`,
    {
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'evidence_citizen' },
    }
  );
  const duration = Date.now() - startTime;

  evidenceCitizenLatency.add(duration);

  const success = check(res, {
    'evidence citizen status is 200 or 404': (r) => r.status === 200 || r.status === 404,
  });

  if (!success && res.status !== 401 && res.status !== 403) {
    evidenceErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }
}

// Scenario 22: Evidence Sanctions Lookup Throughput
export function evidenceSanctionsScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  const nationalID = `19800101-${String(__VU * 1000 + __ITER).padStart(4, '0')}`;

  const startTime = Date.now();
  const res = http.get(
    `${BASE_URL}/evidence/sanctions/${nationalID}`,
    {
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'evidence_sanctions' },
    }
  );
  const duration = Date.now() - startTime;

  evidenceSanctionsLatency.add(duration);

  const success = check(res, {
    'evidence sanctions status is 200': (r) => r.status === 200,
  });

  if (!success && res.status !== 401 && res.status !== 403) {
    evidenceErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }
}

// Scenario 23: Evidence VC Issuance Pipeline
export function evidenceVCIssueScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  const nationalID = DECISION_TEST_PROFILES.valid_adult;

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/evidence/credentials`,
    JSON.stringify({
      national_id: nationalID,
      credential_type: 'age_verification',
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'evidence_vc_issue' },
    }
  );
  const duration = Date.now() - startTime;

  evidenceVCIssueLatency.add(duration);

  const success = check(res, {
    'evidence vc issue status is 200 or 201': (r) => r.status === 200 || r.status === 201,
  });

  if (!success && res.status !== 401 && res.status !== 403) {
    evidenceErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }
}

// Scenario 24: Evidence Cache Stampede
export function evidenceCacheStampedeScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  // All VUs hit the same national ID to simulate stampede
  const nationalID = '19800101-STAMPEDE';

  const startTime = Date.now();
  const res = http.get(
    `${BASE_URL}/evidence/check/${nationalID}`,
    {
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'evidence_cache_stampede' },
    }
  );
  const duration = Date.now() - startTime;

  evidenceCheckLatency.add(duration);

  check(res, {
    'evidence stampede response valid': (r) => r.status === 200 || r.status === 404 || r.status === 401,
  });
}

// Scenario 25: Evidence Check (Combined) Throughput
export function evidenceCheckScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  // Mix of repeated IDs (cache hits) and unique IDs (cache misses)
  let nationalID;
  if (Math.random() < 0.7) {
    // 70% cache hits - use from small pool
    const hotIDs = ['19800101-HOT1', '19800101-HOT2', '19800101-HOT3', '19800101-HOT4', '19800101-HOT5'];
    nationalID = hotIDs[Math.floor(Math.random() * hotIDs.length)];
    evidenceCacheHits.add(1);
  } else {
    // 30% cache misses - unique IDs
    nationalID = `19800101-${__VU}-${__ITER}`;
    evidenceCacheMisses.add(1);
  }

  const startTime = Date.now();
  const res = http.get(
    `${BASE_URL}/evidence/check/${nationalID}`,
    {
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'evidence_check' },
    }
  );
  const duration = Date.now() - startTime;

  evidenceCheckLatency.add(duration);

  const success = check(res, {
    'evidence check status valid': (r) => r.status === 200 || r.status === 404,
  });

  if (!success && res.status !== 401 && res.status !== 403) {
    evidenceErrors.add(1);
    errorRate.add(1);
  } else {
    errorRate.add(0);
  }
}

// ========== ADDITIONAL AUTH SCENARIO IMPLEMENTATIONS ==========

// Shared state for auth code replay test
let sharedAuthCodes = [];

// Scenario 26: Auth Code Replay Attack
export function authCodeReplayScenario(data) {
  const clientID = data.clientID || CLIENT_ID;

  // First iteration: get a fresh auth code
  if (__ITER === 0) {
    const email = `replay-test-${__VU}@example.com`;
    const authRes = http.post(
      `${BASE_URL}/auth/authorize`,
      JSON.stringify({
        email,
        client_id: clientID,
        redirect_uri: REDIRECT_URI,
        scopes: DEFAULT_SCOPES,
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );

    if (authRes.status === 200) {
      try {
        const body = JSON.parse(authRes.body);
        sharedAuthCodes[__VU] = body.code;
      } catch {
        // Ignore
      }
    }
  }

  // All iterations: try to use the same code (should fail after first use)
  const code = sharedAuthCodes[__VU];
  if (!code) {
    return;
  }

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/auth/token`,
    JSON.stringify({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: clientID,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { name: 'auth_code_replay' },
    }
  );
  const duration = Date.now() - startTime;

  authCodeReplayLatency.add(duration);

  if (__ITER === 0) {
    // First use should succeed
    check(res, {
      'first code use succeeds': (r) => r.status === 200,
    });
  } else {
    // Subsequent uses should fail with replay error
    const isReplayBlocked = check(res, {
      'replay attempt blocked': (r) => r.status === 400 || r.status === 401,
    });
    if (!isReplayBlocked) {
      authCodeReplayErrors.add(1);
      console.log(`SECURITY: Auth code replay succeeded on attempt ${__ITER}!`);
    }
  }
}

// Scenario 27: TRL Write Saturation
export function trlWriteSaturationScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];

  const startTime = Date.now();
  const res = http.post(
    `${BASE_URL}/auth/revoke`,
    JSON.stringify({
      token: token.accessToken,
      token_type_hint: 'access_token',
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'trl_write' },
    }
  );
  const duration = Date.now() - startTime;

  trlWriteLatency.add(duration);

  check(res, {
    'trl write response valid': (r) => r.status === 200 || r.status === 204 || r.status === 400,
  });
}

// Scenario 28: Userinfo Endpoint Throughput
export function userinfoThroughputScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];

  const startTime = Date.now();
  const res = http.get(
    `${BASE_URL}/auth/userinfo`,
    {
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
      },
      tags: { name: 'userinfo' },
    }
  );
  const duration = Date.now() - startTime;

  userinfoLatency.add(duration);

  check(res, {
    'userinfo status is 200': (r) => r.status === 200,
    'userinfo has sub': (r) => {
      try {
        return JSON.parse(r.body).sub !== undefined;
      } catch {
        return false;
      }
    },
  });
}

// ========== ADDITIONAL CONSENT SCENARIO IMPLEMENTATIONS ==========

// Scenario 29: Consent Revoke/Grant Race
export function consentRevokeGrantRaceScenario(data) {
  const token = data.tokens[(__VU - 1) % data.tokens.length];
  const purpose = CONSENT_PURPOSES[__ITER % CONSENT_PURPOSES.length];

  // Alternate between grant and revoke
  if (__ITER % 2 === 0) {
    // Grant
    const startTime = Date.now();
    const res = http.post(
      `${BASE_URL}/auth/consent`,
      JSON.stringify({ purposes: [purpose] }),
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token.accessToken}`,
        },
        tags: { name: 'consent_grant_race' },
      }
    );
    consentGrantLatency.add(Date.now() - startTime);
    check(res, { 'consent grant valid': (r) => r.status === 200 || r.status === 201 || r.status === 400 });
  } else {
    // Revoke
    const startTime = Date.now();
    const res = http.post(
      `${BASE_URL}/auth/consent/revoke`,
      JSON.stringify({ purposes: [purpose] }),
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token.accessToken}`,
        },
        tags: { name: 'consent_revoke_race' },
      }
    );
    consentRevokeLatency.add(Date.now() - startTime);
    check(res, { 'consent revoke valid': (r) => r.status === 200 || r.status === 204 || r.status === 400 });
  }

  sleep(0.1);
}

// Scenario 30: Consent GDPR Delete
export function consentGDPRDeleteScenario(data) {
  const clientID = data.clientID || CLIENT_ID;
  // Create fresh user for each iteration to test delete
  const email = `gdpr-delete-${__VU}-${__ITER}@example.com`;

  // Step 1: Create user via authorize
  const authRes = http.post(
    `${BASE_URL}/auth/authorize`,
    JSON.stringify({
      email,
      client_id: clientID,
      redirect_uri: REDIRECT_URI,
      scopes: DEFAULT_SCOPES,
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  if (authRes.status !== 200) {
    return;
  }

  const code = JSON.parse(authRes.body).code;

  // Step 2: Exchange for tokens
  const tokenRes = http.post(
    `${BASE_URL}/auth/token`,
    JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientID,
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  if (tokenRes.status !== 200) {
    return;
  }

  const accessToken = JSON.parse(tokenRes.body).access_token;

  // Step 3: Grant some consents
  http.post(
    `${BASE_URL}/auth/consent`,
    JSON.stringify({ purposes: CONSENT_PURPOSES }),
    {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
    }
  );

  // Step 4: Delete all consents (GDPR)
  const startTime = Date.now();
  const deleteRes = http.del(
    `${BASE_URL}/auth/consent`,
    null,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
      tags: { name: 'consent_gdpr_delete' },
    }
  );
  consentDeleteLatency.add(Date.now() - startTime);

  check(deleteRes, {
    'consent delete status valid': (r) => r.status === 200 || r.status === 204,
  });

  // Step 5: Verify deletion - list should be empty
  const listRes = http.get(
    `${BASE_URL}/auth/consent`,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    }
  );

  check(listRes, {
    'consent list empty after delete': (r) => {
      try {
        const body = JSON.parse(r.body);
        return Array.isArray(body.consents) && body.consents.length === 0;
      } catch {
        return r.status === 200; // Accept if response is valid
      }
    },
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
