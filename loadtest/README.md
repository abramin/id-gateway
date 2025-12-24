# Credo Load Testing

Load test suite using [k6](https://k6.io) to validate performance improvements.

## Installation

```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Docker
docker pull grafana/k6
```

## Quick Smoke Test

Verify the server is responding before running full load tests:

```bash
# Start the server
make run

# In another terminal, run smoke test
k6 run loadtest/k6-quick.js
```

## Full Load Test Suite

### Prerequisites

1. Start the server with rate limiting disabled (required for most load tests):

```bash
# Recommended for load testing
DISABLE_RATE_LIMITING=true docker compose up

# Or with make
DISABLE_RATE_LIMITING=true make run
```

> **Note**: Rate limiting must be disabled for most scenarios. The setup phase creates
> many resources (tenants, clients, users) which will trigger rate limits otherwise.
> Only the `rate_limit_*` scenarios should run with rate limiting enabled.

2. The script is self-bootstrapping in local/dev environments:
   - It automatically uses `demo-admin-token` (matching the server's default)
   - It creates a temporary tenant and client on each run
   - No additional configuration needed for local testing

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8080` | Server URL |
| `ADMIN_TOKEN` | `demo-admin-token` | Admin API token |
| `CLIENT_ID` | (auto-created) | Use existing client |
| `USER_COUNT` | `200` | Test users to create |
| `BURST_CLIENT_COUNT` | `100` | Clients for ResolveClient burst |
| `LARGE_TENANT_CLIENT_COUNT` | `500` | Clients per large tenant |
| `SCOPES` | `openid,profile` | OAuth scopes |
| `SCENARIO` | `all` | Which scenario to run |

### Run Scenarios

```bash
# Run all scenarios (requires DISABLE_RATE_LIMITING=true)
k6 run loadtest/k6-credo.js

# Run specific scenario
k6 run loadtest/k6-credo.js -e SCENARIO=token_refresh_storm
k6 run loadtest/k6-credo.js -e SCENARIO=resolve_client_burst
k6 run loadtest/k6-credo.js -e SCENARIO=client_onboarding_spike

# With fewer users for quick testing
k6 run loadtest/k6-credo.js -e USER_COUNT=10

# Test rate limiting behavior (run WITH rate limiting enabled)
k6 run loadtest/k6-credo.js -e SCENARIO=rate_limit_sustained
k6 run loadtest/k6-credo.js -e SCENARIO=rate_limit_cardinality
```

## Scenarios

### 1. Token Refresh Storm (`token_refresh_storm`)

**Purpose**: Validate mutex contention under concurrent token refresh load

- **Load**: 100 req/sec for 5 minutes
- **VUs**: 50-200 virtual users
- **Target**: p95 latency < 200ms, error rate < 0.1%

### 2. Consent Grant Burst (`consent_burst`)

**Purpose**: Validate consent service throughput with multi-purpose grants

- **Load**: Ramp from 10 to 50 req/sec over 5 minutes
- **VUs**: 20-100 virtual users
- **Target**: p95 latency < 300ms

### 3. Mixed Load (`mixed_load`)

**Purpose**: Validate read performance during write contention

- **Load**: 50 concurrent users, 70% reads / 30% writes
- **Duration**: 5 minutes
- **Target**: List p95 < 100ms, Refresh p95 < 300ms

### 4. OAuth Flow Storm (`oauth_flow_storm`)

**Purpose**: Test full authorize → token exchange path under load

- **Load**: 50 full OAuth flows per second
- **Duration**: 5 minutes
- **Target**: p95 < 500ms for full flow

### 5. ResolveClient Burst (`resolve_client_burst`)

**Purpose**: Validate ResolveClient performance with 1000 concurrent calls against 100 clients

- **Load**: 200 req/sec for 1 minute
- **Setup**: Creates 100 clients
- **Target**: p95 latency < 100ms (cache justification baseline)

### 6. Client Onboarding Spike (`client_onboarding_spike`)

**Purpose**: Measure bcrypt contention under concurrent CreateClient requests

- **Load**: 50 concurrent VUs for 2 minutes
- **Endpoint**: `POST /admin/clients`
- **Target**: p95 latency < 500ms (bcrypt ~100ms per hash)

### 7. Tenant Dashboard Load (`tenant_dashboard_load`)

**Purpose**: Validate GetTenant performance for tenants with 500+ clients

- **Load**: 100 concurrent VUs for 2 minutes
- **Setup**: Creates tenant with 500 clients
- **Target**: p95 latency < 100ms (COUNT queries should be O(1))

### 8. Rate Limit Sustained (`rate_limit_sustained`)

**Purpose**: Validate rate limiting under sustained high request rate

- **Load**: 500 req/sec for 1 minute
- **Expected**: 429 responses after limit is reached
- **Run with**: Rate limiting ENABLED

### 9. Rate Limit Cardinality (`rate_limit_cardinality`)

**Purpose**: Test memory behavior under many unique IPs

- **Load**: 50 VUs × 100 iterations (5000 unique IPs)
- **Method**: X-Forwarded-For header spoofing
- **Run with**: Rate limiting ENABLED

## Metrics Collected

| Metric                   | Description                          |
| ------------------------ | ------------------------------------ |
| `token_refresh_latency`  | Token refresh endpoint latency       |
| `consent_grant_latency`  | Consent grant endpoint latency       |
| `session_list_latency`   | Session list endpoint latency        |
| `oauth_flow_latency`     | Full OAuth flow latency              |
| `authorize_latency`      | Authorize endpoint latency           |
| `token_exchange_latency` | Token exchange latency               |
| `resolve_client_latency` | ResolveClient call latency           |
| `create_client_latency`  | CreateClient endpoint latency        |
| `get_tenant_latency`     | GetTenant endpoint latency           |
| `rate_limit_latency`     | Health endpoint latency (rate tests) |
| `rate_limited_count`     | Count of 429 responses               |
| `token_errors`           | Count of token refresh failures      |
| `consent_errors`         | Count of consent grant failures      |
| `error_rate`             | Overall error rate                   |

## Viewing Results

### Terminal Output

k6 prints summary statistics after each run.

### JSON Output

```bash
k6 run --out json=results.json loadtest/k6-credo.js
```

### InfluxDB + Grafana

```bash
# Start InfluxDB
docker run -d --name influxdb -p 8086:8086 influxdb:1.8

# Run with InfluxDB output
k6 run --out influxdb=http://localhost:8086/k6 loadtest/k6-credo.js
```

## Interpreting Results

### Healthy Results

```
     token_refresh_latency...: avg=45ms   p(95)=120ms  p(99)=180ms
     error_rate...............: 0.02%
     http_reqs................: 30000   100/s
```

### Concerning Results

```
     token_refresh_latency...: avg=450ms  p(95)=1200ms p(99)=2500ms
     error_rate...............: 5.2%
     http_reqs................: 15000   50/s
```

**Signs of mutex contention**:

- p99 >> p95 (long tail latencies)
- Throughput plateaus despite adding VUs
- Error rate increases under load

## Profiling During Load Tests

While running load tests, capture profiling data:

```bash
# CPU profile (30 seconds)
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Mutex contention
go tool pprof http://localhost:8080/debug/pprof/mutex

# Block profile (goroutine blocking)
go tool pprof http://localhost:8080/debug/pprof/block

# Goroutine count
curl http://localhost:8080/debug/pprof/goroutine?debug=1 | head -20
```

## Tips

1. **Warm up first**: Run a quick smoke test before full load
2. **Isolate scenarios**: Run one scenario at a time for cleaner metrics
3. **Monitor system resources**: Watch CPU, memory, goroutines during tests
4. **Repeat tests**: Run 3x and average results to reduce noise
5. **Test realistic data**: Use production-like token counts and user distributions
