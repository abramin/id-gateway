# PRD-020: Operational Readiness & SRE

**Status:** Not Started
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Dependencies:** PRD-006 (Audit), all core PRDs
**Last Updated:** 2025-12-27

---

## 1. Overview

### Problem Statement

The system cannot be deployed to production without operational tooling:

- No health check endpoints (Kubernetes liveness/readiness probes fail)
- No backup/restore procedures
- No disaster recovery plan
- No incident response runbooks
- No capacity planning guidelines
- No performance SLAs

### Goals

- Health check endpoints (`/health`, `/ready`, `/live`)
- Liveness vs readiness probes (Kubernetes-compatible)
- Backup & restore procedures
- Disaster recovery plan (RTO/RPO targets)
- Incident response runbooks
- On-call playbooks
- Capacity planning guidelines
- Performance SLAs
- Metrics and alerting baseline for auth, revocation, audit, rate limits, and consent enforcement

### Non-Goals

- Full SRE team hiring plan
- Chaos engineering / fault injection
- Cost optimization strategies

---

## 1B. Storage Infrastructure Transition

### In-Memory First Philosophy

The codebase is intentionally designed with **in-memory stores first, production storage later**. This approach:

- Enables rapid iteration during Phase 0-1 (no external dependencies)
- Keeps tests fast and deterministic
- Uses interfaces throughout, making swapping implementations trivial
- Defers infrastructure complexity until proven necessary

### When to Introduce Production Storage

| Trigger | Required Tool | Rationale |
|---------|--------------|-----------|
| **Multi-instance deployment** | Redis | Rate limiting (PRD-017) must be distributed; in-memory state isn't shared across instances |
| **Data durability requirements** | PostgreSQL | Audit logs (PRD-006), user data, consent records must survive restarts |
| **Compliance/regulatory** | PostgreSQL | GDPR data export requires persistent storage; auditors need durable records |
| **Session sharing** | Redis | Session validation across instances requires shared session store |
| **Backup/DR requirements** | PostgreSQL | Can't backup in-memory stores; `pg_dump` enables point-in-time recovery |
| **Production health checks** | Both | `/health/ready` checks database/Redis connectivity (this PRD) |

### Transition Timeline

```
Phase 0-1 (MVP Development)     → In-memory stores only
Phase 2 (Operational Baseline)  → PostgreSQL (users, consents, audit) + Redis (rate limiting, sessions)
Phase 3+ (Production)           → Message queues (audit events), external caches (CDN)
```

### Migration Path

All stores implement the same interface, so migration is DI wiring only:

```go
// Phase 0-1: In-memory (development/testing)
userStore := inmemory.NewUserStore()

// Phase 2+: PostgreSQL (production)
userStore := postgres.NewUserStore(db)
```

**No business logic changes required.** Services depend on interfaces, not implementations.

### Storage Decision Matrix

| Store | Stay In-Memory When | Migrate to PostgreSQL When | Migrate to Redis When |
|-------|--------------------|-----------------------------|----------------------|
| `UserStore` | Single instance, ephemeral users | Users must persist across deploys | Never (not a cache) |
| `SessionStore` | Single instance, no DR needs | Never (sessions are transient) | Multi-instance deployment |
| `ConsentStore` | Development/testing only | GDPR compliance, audit requirements | Consent projections (CQRS read model) |
| `AuditStore` | Development/testing only | Any production deployment | Never (requires durability) |
| `RateLimitStore` | Single instance | Never | Multi-instance deployment |
| `RegistryCache` | Small dataset, testing | Never (it's a cache) | Large dataset, multi-instance |

### This PRD's Role

PRD-020 marks the transition point. The health checks (`/health/ready`) defined here validate database and Redis connectivity, signaling that production storage is now required.

---

## 2. Functional Requirements

### FR-0: Metrics and Alerting Baseline

**Required metrics:**
- Auth SLIs: p95/p99 latency and error rate for `/auth/authorize`, `/auth/token`, `/auth/revoke`, split by tenant and client.
- Revocation health: TRL write failures, revocation lag, and revoked-token check failures.
- Audit durability: enqueue depth, drop count, persist failures, and time-to-persist.
- Abuse signals: refresh token reuse detections, auth lockouts, and rate-limit denials by IP and client.
- Consent enforcement: consent gating failures and regulated-mode PII minimization violations.

**Required alerts:**
- Sustained auth SLI violations by tenant or client.
- TRL write or check failure spikes; revocation lag above threshold.
- Audit event drops or persist failures above threshold.
- Refresh token reuse spike or auth lockout surge.
- Consent gating failures above baseline.

### FR-1: Health Check Endpoints

**Endpoint:** `GET /health/live`

**Purpose:** Kubernetes liveness probe (is process alive?)

**Response (200):**

```json
{
  "status": "ok",
  "timestamp": "2025-12-12T10:00:00Z"
}
```

**Logic:** Return 200 if server is running, 500 if panicking

---

**Endpoint:** `GET /health/ready`

**Purpose:** Kubernetes readiness probe (can accept traffic?)

**Response (200):**

```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "redis": "ok",
    "registry_api": "ok"
  },
  "timestamp": "2025-12-12T10:00:00Z"
}
```

**Response (503 if not ready):**

```json
{
  "status": "not_ready",
  "checks": {
    "database": "ok",
    "redis": "failed",
    "registry_api": "ok"
  },
  "timestamp": "2025-12-12T10:00:00Z"
}
```

**Logic:**

- Check database connection
- Check Redis connection
- Check external API reachability
- Return 503 if any check fails

**Provider Health Checks** (identified gap from module README):

The `/health/ready` endpoint should include health checks for registered registry providers. Each provider exposes a `Health()` method through the provider interface that returns availability status.

- Wire provider `Health()` methods to the readiness probe
- Include per-provider health status in the `checks` response (e.g., `"citizen_provider": "ok"`, `"sanctions_provider": "degraded"`)
- Support configurable provider health thresholds (e.g., mark ready if 2-of-3 providers are healthy)
- Emit metrics for provider health state changes
- Log provider health check failures with circuit breaker context

**Example Response with Provider Checks:**

```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "redis": "ok",
    "providers": {
      "citizen": "ok",
      "sanctions": "ok",
      "biometric": "degraded"
    }
  },
  "timestamp": "2025-12-27T10:00:00Z"
}
```

---

**Endpoint:** `GET /health`

**Purpose:** General health status

**Response:**

```json
{
  "status": "healthy",
  "version": "1.2.3",
  "uptime_seconds": 86400,
  "checks": {
    "database": "ok",
    "redis": "ok",
    "registry": "ok"
  }
}
```

---

### FR-2: Backup & Restore

**Database Backup:**

```bash
# Daily automated backup
pg_dump -h localhost -U credo credo_db > backup_$(date +%Y%m%d).sql

# Upload to S3
aws s3 cp backup_$(date +%Y%m%d).sql s3://credo-backups/
```

**Backup Schedule:**

- **Daily:** Full database backup (retained 30 days)
- **Hourly:** Incremental logs (retained 7 days)
- **Weekly:** Full snapshot (retained 90 days)

**Restore Procedure:**

```bash
# Download from S3
aws s3 cp s3://credo-backups/backup_20251212.sql .

# Restore
psql -h localhost -U credo credo_db < backup_20251212.sql
```

**Encryption:** All backups encrypted at rest (AES-256)

---

### FR-3: Disaster Recovery Plan

**Recovery Time Objective (RTO):** 4 hours
**Recovery Point Objective (RPO):** 1 hour

**DR Scenarios:**

| Scenario             | Likelihood | Impact   | Recovery Steps                                |
| -------------------- | ---------- | -------- | --------------------------------------------- |
| **Database failure** | Medium     | High     | Restore from latest backup, replay logs       |
| **Redis failure**    | Medium     | Medium   | Rebuild cache from database, gradual recovery |
| **Region outage**    | Low        | Critical | Failover to DR region, DNS update             |
| **Data corruption**  | Low        | High     | Point-in-time recovery from backup            |

**DR Testing:** Quarterly DR drills

---

### FR-4: Incident Response Runbooks

**Location:** `docs/runbooks/`

**Runbooks:**

1. **High Error Rate**

   - Check `/metrics` for error codes
   - Check logs for stack traces
   - Scale up if CPU/memory constrained
   - Rollback recent deployment if regression

2. **Database Connection Pool Exhaustion**

   - Check active connections: `SELECT count(*) FROM pg_stat_activity;`
   - Kill long-running queries
   - Increase pool size temporarily
   - Investigate slow queries

3. **Rate Limit Exceeded Alerts**

   - Check top IPs from rate limit logs
   - Confirm legitimate vs attack traffic
   - Add attacker IPs to blocklist
   - Scale rate limiter if needed

4. **Registry API Down**
   - Check registry API health
   - Enable graceful degradation (cached responses)
   - Notify users of degraded service
   - Contact registry provider

---

### FR-5: Performance SLAs

**Latency Targets:**

| Endpoint Class | p50     | p95     | p99     | Timeout |
| -------------- | ------- | ------- | ------- | ------- |
| **Auth**       | < 50ms  | < 100ms | < 200ms | 5s      |
| **Consent**    | < 30ms  | < 80ms  | < 150ms | 3s      |
| **Registry**   | < 200ms | < 500ms | < 1s    | 10s     |
| **Decision**   | < 100ms | < 300ms | < 800ms | 5s      |
| **Audit**      | < 20ms  | < 50ms  | < 100ms | 2s      |

**Availability Target:** 99.9% uptime (43 minutes downtime/month)

**Error Budget:** 0.1% (allows ~260 req failures per 1M requests)

---

### FR-6: Capacity Planning

**Current Capacity:**

- 2 instances x 2 CPU x 4GB RAM
- Database: 100GB storage
- Redis: 8GB memory

**Growth Projections:**

| Metric            | Current | 6mo  | 12mo  |
| ----------------- | ------- | ---- | ----- |
| **Users**         | 10K     | 50K  | 200K  |
| **Requests/day**  | 1M      | 5M   | 20M   |
| **Database size** | 10GB    | 50GB | 200GB |
| **Instances**     | 2       | 5    | 10    |

**Scaling Triggers:**

- CPU > 70% sustained → scale up
- Memory > 80% sustained → scale up
- Request latency p95 > 2x target → scale up

---

## 3. Implementation Steps

### Phase 1: Health Checks (2-3 hours)

1. Implement `/health/live` endpoint
2. Implement `/health/ready` with dependency checks
3. Configure Kubernetes probes

### Phase 2: Backup & DR (3-4 hours)

1. Create backup scripts
2. Configure S3 bucket with lifecycle policies
3. Test restore procedure
4. Document DR plan

### Phase 3: Runbooks (3-4 hours)

1. Write incident response runbooks
2. Create on-call rotation
3. Set up PagerDuty/Opsgenie
4. Conduct DR drill

---

## 4. Acceptance Criteria

- [ ] `/health/live` returns 200 when server running
- [ ] `/health/ready` returns 503 when database down
- [ ] Kubernetes probes configured in deployment.yaml
- [ ] Daily backups running and uploaded to S3
- [ ] Restore tested successfully
- [ ] DR plan documented with RTO/RPO
- [ ] 5+ runbooks created
- [ ] Performance SLAs documented
- [ ] Capacity planning spreadsheet created
- [ ] On-call rotation established

---

## 5. Monitoring Alerts

**Critical Alerts (Page immediately):**

- Service down (all instances)
- Error rate > 5%
- p99 latency > 5s
- Database connection failures

**Warning Alerts (Slack notification):**

- Error rate > 1%
- p95 latency > 2x target
- CPU > 70%
- Memory > 80%

---

## Revision History

| Version | Date       | Author       | Changes                                                                                          |
| ------- | ---------- | ------------ | ------------------------------------------------------------------------------------------------ |
| 1.2     | 2025-12-27 | Engineering  | Added provider health checks to FR-1 (identified gap from module README)                          |
| 1.1     | 2025-12-21 | Engineering  | Added Section 1B: Storage Infrastructure Transition (in-memory first philosophy, migration triggers, decision matrix) |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                                                                      |
