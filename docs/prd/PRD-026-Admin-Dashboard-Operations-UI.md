# PRD-026: Admin Dashboard & Operations UI

**Status:** Not Started
**Priority:** P2 (Medium)
**Owner:** Engineering Team
**Dependencies:** PRD-001-007, PRD-020
**Last Updated:** 2025-12-18

## 1. Overview

### Problem Statement
Requires SQL access for basic operations - high operational overhead, error-prone.

### Goals
- User search & management
- Session management (view, revoke)
- Consent audit viewer
- System health monitoring
- Configuration management
- Role-based admin access
- Bulk operations (user import, consent reset)

## 2. Functional Requirements

### FR-1: User Management
**Features:**
- Search users by email/ID
- View user details
- Lock/unlock accounts
- Reset passwords (admin-initiated)
- View audit trail per user

### FR-2: Session Management
**Features:**
- List all active sessions
- View session details (device, IP, last activity)
- Revoke sessions (force logout)
- View session history

### FR-3: Consent Management
**Features:**
- View all consent records
- Bulk consent operations
- Export consent reports
- View consent timeline per user

### FR-4: System Health
**Features:**
- Service status dashboard
- Metrics visualization (Grafana embedded)
- Recent error logs
- Performance charts

### FR-5: Configuration UI
**Features:**
- Edit rate limits
- Manage feature flags
- Update email templates
- Configure MFA policies

### FR-5B: Tenant Governance & Settings
**Features:**
- Manage tenant-level security policies (password rules, MFA required, session limits)
- Create/manage tenant teams or org units
- Assign users to teams and roles (tenant-scoped)

### FR-6: Security Operations & Fraud Detection Controls

**Dependencies:** PRD-023 (Fraud Detection), PRD-027 (Adaptive Auth)

**Purpose:** Provide operational controls for security detectors, risk thresholds, and adaptive authentication policies.

#### FR-6.1: Detector On/Off Toggles

**Features:**
- Enable/disable individual fraud detectors without deployment
- Toggle switches for:
  - Impossible travel detection
  - Bot detection (good/bad lists)
  - Payload anomaly checks
  - Device drift detection
  - Account graphing (mule detection)
  - Replay detection

**UI:**

```
┌─────────────────────────────────────────────────────┐
│ Fraud Detectors                                     │
├─────────────────────────────────────────────────────┤
│ ☑ Impossible Travel Detection        [ENABLED  ▼]  │
│   Velocity Threshold: 800 km/h       [Edit]        │
│                                                     │
│ ☑ Bot Detection                      [ENABLED  ▼]  │
│   Bad Bot Blocking: On               [Edit List]   │
│   Tarpitting: On                                    │
│                                                     │
│ ☐ Payload Anomaly Detection          [DISABLED ▼]  │
│   Entropy Threshold: 4.5             [Edit]        │
│                                                     │
│ ☑ Device Drift Detection             [ENABLED  ▼]  │
│   Drift Threshold: 20                [Edit]        │
│                                                     │
│ ☑ Account Graphing                   [ENABLED  ▼]  │
│   Device Sharing: >5 users           [Edit]        │
│   IP Sharing: >10 users              [Edit]        │
│                                                     │
│ ☑ Replay Detection                   [ENABLED  ▼]  │
│   Nonce TTL: 5 minutes               [Edit]        │
└─────────────────────────────────────────────────────┘
```

**Backend:**

```sql
-- Store in config table or YAML
UPDATE fraud_detection_config
SET enabled = false
WHERE detector_name = 'payload_anomaly';
```

#### FR-6.2: Risk Score Thresholds Tuning

**Features:**
- Adjust risk score band thresholds
- Configure per-event-type thresholds
- Real-time updates without restart

**UI:**

```
┌─────────────────────────────────────────────────────┐
│ Risk Score Thresholds                               │
├─────────────────────────────────────────────────────┤
│ Global Thresholds:                                  │
│   Low Risk:      [  0] - [ 20]  (Allow)            │
│   Medium Risk:   [ 21] - [ 50]  (Log & Monitor)    │
│   High Risk:     [ 51] - [ 75]  (Require MFA)      │
│   Critical Risk: [ 76] - [100]  (Deny & Lock)      │
│                                                     │
│ Per-Event Overrides:                                │
│   VC Issuance:   Medium → [Require MFA]     [Edit] │
│   Login:         High → [Require MFA]        [Edit] │
│   Data Export:   Medium → [Require Re-Auth]  [Edit] │
│                                                     │
│                          [Save Changes] [Revert]    │
└─────────────────────────────────────────────────────┘
```

**API:**

```bash
# Update global threshold
PUT /admin/risk-thresholds/global
{
  "low_max": 20,
  "medium_max": 50,
  "high_max": 75
}

# Update event-specific policy
PUT /admin/risk-policies
{
  "event_type": "vc_issuance",
  "risk_min": 21,
  "risk_max": 50,
  "action": "require_mfa"
}
```

#### FR-6.3: Shadow Mode for Testing

**Features:**
- Enable shadow mode per detector or policy
- Compare shadow decisions vs. real decisions
- Review shadow mode logs before enforcement

**UI:**

```
┌─────────────────────────────────────────────────────┐
│ Shadow Mode Testing                                 │
├─────────────────────────────────────────────────────┤
│ Active Shadow Tests:                                │
│                                                     │
│ ☑ Impossible Travel - New Threshold (800 → 600 km/h)│
│   Started: 2025-12-10 10:00                         │
│   Duration: 48 hours                                │
│   Would-Have-Blocked: 23 requests                   │
│   False Positives: 2 (8.7%)           [Review]      │
│                                                     │
│ ☑ Account Graphing - Stricter Limit (>5 → >3)      │
│   Started: 2025-12-11 14:00                         │
│   Duration: 72 hours                                │
│   Would-Have-Blocked: 8 requests                    │
│   False Positives: 0 (0%)             [Review]      │
│                                                     │
│ [+ New Shadow Test]                                 │
└─────────────────────────────────────────────────────┘
```

**Workflow:**

1. Admin creates shadow test (new threshold or policy)
2. System logs what would happen but doesn't enforce
3. After test period, admin reviews results
4. If acceptable, promote to active policy
5. If not, discard or adjust

**API:**

```bash
# Enable shadow mode for policy
PUT /admin/risk-policies/{policy_id}
{
  "shadow_mode": true,
  "shadow_duration_hours": 48
}

# Review shadow mode results
GET /admin/risk-policies/{policy_id}/shadow-results
# Returns: would-have-blocked count, false positives, etc.

# Promote shadow policy to active
POST /admin/risk-policies/{policy_id}/activate
```

#### FR-6.4: Simple Dashboards

**Features:**
- Request counts by risk level
- Suspicious events per detector
- Blocked requests over time
- Top high-risk users
- Geographic distribution of risk

**Grafana Dashboard Panels:**

1. **Risk Score Distribution (Histogram)**
   - X-axis: Risk score bands (0-20, 21-50, 51-75, 76-100)
   - Y-axis: Request count
   - Stacked by event type

2. **Detector Trigger Rate (Time Series)**
   - Lines for each detector (impossible travel, bot, payload, device drift)
   - Y-axis: Triggers per hour
   - Alert threshold overlay

3. **Blocked Requests (Table)**
   - Columns: Time, User, Risk Score, Detector, Action
   - Sortable, filterable
   - Click to view details

4. **Geographic Risk Map**
   - World map with color-coded risk levels by country
   - Hover to see stats (avg risk score, flagged users)

5. **Adaptive Auth Actions (Pie Chart)**
   - Slices: Allow, Require MFA, Deny, Soft Lock
   - Percentage of total requests

6. **Shadow Mode Comparison (Bar Chart)**
   - Side-by-side: Current policy vs. Shadow policy
   - Metrics: Blocks, False positives, User friction

**Metrics Required:**

```
# From PRD-023
fraud_risk_scores_total{result="low|medium|high|critical"}
fraud_detector_triggered_total{detector="..."}
fraud_requests_blocked_total{reason="..."}

# From PRD-027
adaptive_auth_actions_total{action="allow|require_mfa|deny|soft_lock"}
adaptive_auth_shadow_decisions_total{action="..."}
```

**Dashboard Access:**

- Embedded Grafana iframe: `/admin/dashboard/security`
- Direct link to Grafana: Config in admin settings
- Export PNG/PDF reports for compliance

#### FR-6.5: Manual Review Queue

**Features:**
- View operations pending manual review
- Approve or deny with notes
- Bulk approve/deny
- SLA tracking (time to review)

**UI:**

```
┌─────────────────────────────────────────────────────────────────────┐
│ Manual Review Queue (12 pending)                    [Refresh]       │
├──────────┬──────────┬────────────┬──────┬─────────┬─────────────────┤
│ Time     │ User     │ Operation  │ Risk │ Reason  │ Actions         │
├──────────┼──────────┼────────────┼──────┼─────────┼─────────────────┤
│ 10:32 AM │ alice@.. │ VC Issue   │  78  │ Travel  │ [Approve][Deny] │
│ 10:15 AM │ bob@...  │ Export     │  82  │ Device  │ [Approve][Deny] │
│ 09:50 AM │ carol@.. │ Password   │  65  │ IP      │ [Approve][Deny] │
│ ...      │ ...      │ ...        │  ... │ ...     │ ...             │
└──────────┴──────────┴────────────┴──────┴─────────┴─────────────────┘
  [☑ Select All]  [Bulk Approve]  [Bulk Deny]
```

**Detail View:**

```
┌─────────────────────────────────────────────────────┐
│ Review Details - alice@example.com                  │
├─────────────────────────────────────────────────────┤
│ Operation:     Issue VC (ProofOfAddress)            │
│ Risk Score:    78 (Critical)                        │
│ Flagged By:    Impossible Travel Detector           │
│ Details:       Login from New York → London (1200 km/h)│
│                                                     │
│ User History:                                       │
│   - Account age: 30 days                            │
│   - Previous flags: 0                               │
│   - MFA enrolled: Yes (TOTP)                        │
│                                                     │
│ Risk Factors:                                       │
│   [+40] Impossible travel (NY → London)             │
│   [+20] IP change                                   │
│   [+15] User agent drift                            │
│   [+3 ] New device                                  │
│                                                     │
│ Reviewer Notes:                                     │
│ [Text area for notes]                               │
│                                                     │
│                      [Approve] [Deny] [Escalate]    │
└─────────────────────────────────────────────────────┘
```

**API:**

```bash
# List pending reviews
GET /admin/review-queue?status=pending

# Get review details
GET /admin/review-queue/{id}

# Approve
POST /admin/review-queue/{id}/approve
{
  "notes": "Verified user via phone call, legitimate travel"
}

# Deny
POST /admin/review-queue/{id}/deny
{
  "notes": "Unable to verify, recommend account lock"
}
```

#### FR-6.6: Allowlist/Denylist Management

**Features:**
- Manage IP allowlists (corporate offices, VPNs)
- Manage device allowlists (shared kiosks)
- View current lists
- Add/remove entries with reason and expiry

**UI:**

```
┌─────────────────────────────────────────────────────────────────────┐
│ IP Allowlist (5 entries)                            [+ Add IP]      │
├────────────────┬──────────────────────┬────────────┬───────────────┤
│ IP / Range     │ Reason               │ Expires    │ Actions       │
├────────────────┼──────────────────────┼────────────┼───────────────┤
│ 203.0.113.0/24 │ Corporate HQ         │ Never      │ [Edit][Delete]│
│ 198.51.100.45  │ Partner VPN          │ 2026-01-01 │ [Edit][Delete]│
│ 192.0.2.100    │ Testing Lab          │ 2025-12-31 │ [Edit][Delete]│
└────────────────┴──────────────────────┴────────────┴───────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ Bot Allowlist (3 entries)                           [+ Add Bot]     │
├────────────────────────┬──────────────────┬───────────────────────┤
│ User-Agent Pattern     │ DNS Verification │ Actions              │
├────────────────────────┼──────────────────┼───────────────────────┤
│ Googlebot              │ *.googlebot.com  │ [Edit][Delete]       │
│ Bingbot                │ *.search.msn.com │ [Edit][Delete]       │
│ ELB-HealthChecker/*    │ None             │ [Edit][Delete]       │
└────────────────────────┴──────────────────┴───────────────────────┘
```

**Non-Goals (Explicitly Excluded):**
- A/B testing frameworks (too complex for MVP)
- ML drift monitoring (PRD-007B territory)
- Real-time alert configuration (use existing monitoring)
- Custom dashboard builder (use Grafana)

## 3. Technical Stack

**Frontend:** React + TypeScript
**Backend:** Existing API + admin endpoints
**Auth:** Admin role required (JWT with `role:admin`)

## 4. Technical Requirements

### TR-1: SQL Query Patterns for Admin Operations

**Objective:** Demonstrate intermediate-to-advanced SQL capabilities for admin dashboard and operations.

**Query Patterns Required:**

- **CTEs for Paginated User Search with Aggregates:**
  ```sql
  WITH user_stats AS (
    SELECT u.id, u.email, u.created_at,
           COUNT(DISTINCT s.id) AS session_count,
           COUNT(DISTINCT c.id) AS consent_count,
           MAX(s.last_activity) AS last_active
    FROM users u
    LEFT JOIN sessions s ON u.id = s.user_id AND s.status = 'active'
    LEFT JOIN consent_records c ON u.id = c.user_id AND c.revoked_at IS NULL
    WHERE u.tenant_id = :tenant_id  -- RLS scoping
      AND (u.email ILIKE :search OR u.id::text ILIKE :search)
    GROUP BY u.id
  )
  SELECT * FROM user_stats
  ORDER BY last_active DESC NULLS LAST
  LIMIT :page_size OFFSET :offset;
  ```

- **Window Functions for Session Timeline:**
  ```sql
  SELECT s.id, s.user_id, s.created_at, s.last_activity,
         ROW_NUMBER() OVER (PARTITION BY s.user_id ORDER BY s.created_at DESC) AS session_rank,
         LAG(s.created_at) OVER (PARTITION BY s.user_id ORDER BY s.created_at) AS prev_session,
         s.created_at - LAG(s.created_at) OVER (PARTITION BY s.user_id ORDER BY s.created_at) AS gap
  FROM sessions s
  WHERE s.user_id = :user_id
    AND s.tenant_id = :tenant_id  -- RLS
  ORDER BY s.created_at DESC;
  ```

- **CASE for Consent Status Categorization:**
  ```sql
  SELECT
    purpose,
    COUNT(*) AS total,
    SUM(CASE
      WHEN revoked_at IS NOT NULL THEN 1
      WHEN expires_at < NOW() THEN 1
      ELSE 0
    END) AS inactive_count,
    SUM(CASE
      WHEN revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) THEN 1
      ELSE 0
    END) AS active_count
  FROM consent_records
  WHERE tenant_id = :tenant_id
  GROUP BY purpose
  HAVING COUNT(*) > 0
  ORDER BY total DESC;
  ```

- **Subquery for Bulk Operations Preview:**
  ```sql
  -- Preview users affected by bulk session revocation
  SELECT u.id, u.email,
         (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.status = 'active') AS active_sessions,
         (SELECT MAX(last_activity) FROM sessions s WHERE s.user_id = u.id) AS last_seen
  FROM users u
  WHERE u.tenant_id = :tenant_id
    AND u.id IN (
      SELECT DISTINCT user_id FROM sessions
      WHERE created_at < NOW() - INTERVAL '90 days'
        AND status = 'active'
    );
  ```

- **Views for Admin Summaries (Avoid Wide Joins):**
  ```sql
  CREATE VIEW admin_user_summary AS
  SELECT
    u.id, u.email, u.created_at,
    COALESCE(ss.session_count, 0) AS session_count,
    COALESCE(cs.consent_count, 0) AS consent_count,
    COALESCE(cs.active_consent_count, 0) AS active_consent_count,
    ss.last_activity
  FROM users u
  LEFT JOIN LATERAL (
    SELECT COUNT(*) AS session_count, MAX(last_activity) AS last_activity
    FROM sessions WHERE user_id = u.id
  ) ss ON true
  LEFT JOIN LATERAL (
    SELECT COUNT(*) AS consent_count,
           COUNT(*) FILTER (WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())) AS active_consent_count
    FROM consent_records WHERE user_id = u.id
  ) cs ON true;

  -- Use view instead of wide join
  SELECT * FROM admin_user_summary WHERE id = :user_id;
  ```

- **Semi-Join for Permission Checks:**
  ```sql
  -- Only show users admin has access to (tenant scoping)
  SELECT u.*
  FROM users u
  WHERE EXISTS (
    SELECT 1 FROM admin_permissions ap
    WHERE ap.admin_id = :current_admin_id
      AND ap.tenant_id = u.tenant_id
      AND ap.capability = 'user:read'
  );
  ```

**Database Design:**

- **Row-Level Security (RLS):** Enable `ALTER TABLE users ENABLE ROW LEVEL SECURITY;` with policies for tenant isolation
- **Partial Indexes:** `CREATE INDEX idx_active_sessions ON sessions (user_id) WHERE status = 'active';`
- **Materialized View for Dashboard Stats:**
  ```sql
  CREATE MATERIALIZED VIEW dashboard_stats AS
  SELECT
    tenant_id,
    COUNT(DISTINCT u.id) AS total_users,
    COUNT(DISTINCT s.id) FILTER (WHERE s.status = 'active') AS active_sessions,
    COUNT(DISTINCT c.id) FILTER (WHERE c.revoked_at IS NULL) AS active_consents
  FROM users u
  LEFT JOIN sessions s ON u.id = s.user_id
  LEFT JOIN consent_records c ON u.id = c.user_id
  GROUP BY tenant_id
  WITH DATA;

  REFRESH MATERIALIZED VIEW CONCURRENTLY dashboard_stats;
  ```

**Acceptance Criteria (SQL):**
- [ ] User search uses CTEs with aggregate stats and pagination
- [ ] Session timeline uses window functions (ROW_NUMBER, LAG)
- [ ] Consent reports use CASE for status categorization
- [ ] Bulk operation previews use correlated subqueries
- [ ] Admin summaries use views/materialized views (no wide joins)
- [ ] Permission checks use semi-joins (EXISTS)
- [ ] RLS policies enforce tenant isolation at database level
- [ ] All queries parameterized (no SQL injection)

---

## 5. Acceptance Criteria
- [ ] Admin can search and manage users
- [ ] Admin can view and revoke sessions
- [ ] Admin can export consent reports
- [ ] System health dashboard displays metrics
- [ ] Configuration changes applied without restart
- [ ] Admin queries enforce RLS/tenant scoping with parameterized search; summaries use views/materialized views (no ad-hoc wide joins)
- [ ] Admin auth uses short-lived tokens with explicit acquisition flow; CSRF defenses on state-changing operations
- [ ] Role-based admin access: authenticated requests without sufficient capability are rejected with 403 Forbidden _(dependency from [PRD-026A](PRD-026A-Tenant-Client-Management.md))_

## Revision History
| Version | Date       | Author       | Changes                                                                                   |
| ------- | ---------- | ------------ | ----------------------------------------------------------------------------------------- |
| 1.3     | 2025-12-21 | Engineering  | Added TR-1: SQL Query Patterns (CTEs, window functions, CASE, subqueries, views, RLS)    |
| 1.2     | 2025-12-18 | Engineering  | Added role-based admin access criterion (403 for insufficient capability) from PRD-026A  |
| 1.1     | 2025-12-18 | Security Eng | Added RLS/tenant scoping, view-based summaries, short-lived admin auth/CSRF              |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                                                               |
