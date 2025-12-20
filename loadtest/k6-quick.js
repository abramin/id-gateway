// k6 Quick Smoke Test for Credo
// Run: k6 run loadtest/k6-quick.js
//
// A simple smoke test to verify the server is responding correctly
// before running the full load test suite.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

const latency = new Trend('request_latency', true);
const errorRate = new Rate('error_rate');

export const options = {
  vus: 10,
  duration: '30s',
  thresholds: {
    'request_latency': ['p(95)<500'],
    'error_rate': ['rate<0.1'],
  },
};

export default function () {
  // Test 1: Health check (if available)
  let res = http.get(`${BASE_URL}/health`);
  check(res, { 'health check ok': (r) => r.status === 200 || r.status === 404 });

  // Test 2: Token endpoint with JSON body (expect 400 without valid params)
  const start = Date.now();
  res = http.post(
    `${BASE_URL}/auth/token`,
    JSON.stringify({ grant_type: 'invalid' }),
    { headers: { 'Content-Type': 'application/json' } }
  );
  latency.add(Date.now() - start);

  const success = check(res, {
    'token endpoint responds': (r) => r.status !== 0,
    'returns error for invalid grant': (r) => r.status === 400 || r.status === 401,
  });

  errorRate.add(success ? 0 : 1);

  sleep(0.5);
}
