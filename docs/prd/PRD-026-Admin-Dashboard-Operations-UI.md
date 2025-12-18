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

## 4. Acceptance Criteria
- [ ] Admin can search and manage users
- [ ] Admin can view and revoke sessions
- [ ] Admin can export consent reports
- [ ] System health dashboard displays metrics
- [ ] Configuration changes applied without restart
- [ ] Admin queries enforce RLS/tenant scoping with parameterized search; summaries use views/materialized views (no ad-hoc wide joins)
- [ ] Admin auth uses short-lived tokens with explicit acquisition flow; CSRF defenses on state-changing operations
- [ ] Role-based admin access: authenticated requests without sufficient capability are rejected with 403 Forbidden _(dependency from [PRD-026A](PRD-026A-Tenant-Client-Management.md))_

## Revision History
| Version | Date       | Author       | Changes                                                  |
| ------- | ---------- | ------------ | -------------------------------------------------------- |
| 1.2     | 2025-12-18 | Engineering  | Added role-based admin access criterion (403 for insufficient capability) from PRD-026A |
| 1.1     | 2025-12-18 | Security Eng | Added RLS/tenant scoping, view-based summaries, short-lived admin auth/CSRF |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                              |
