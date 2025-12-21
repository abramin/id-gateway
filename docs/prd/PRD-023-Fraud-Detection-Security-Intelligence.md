# PRD-023: Fraud Detection & Security Intelligence (Rule-Based)

**Status:** Not Started
**Priority:** P1 (High)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-005B (Cerbos), PRD-017 (Rate Limiting), PRD-021 (MFA)
**Last Updated:** 2025-12-18

---

## 1. Overview

### Problem Statement

System vulnerable to account takeover, identity fraud, credential stuffing, and abuse without continuous risk assessment. Current authentication is binary (authenticated or not), but real-world threats require continuous evaluation of session risk based on behavioral signals, impossible travel patterns, payload anomalies, and device consistency.

### Goals

- **Continuous session risk scoring** using lightweight rule-based engine (not ML)
- **Impossible travel detection** with ISP/ASN awareness and VPN allowlists
- **Bot and abuse countermeasures** (good/bad bot lists, tarpitting, optional WebAuthn challenge)
- **Payload anomaly detection** (header anomalies, form field entropy, replay detection, nonce/clock skew)
- **Device consistency checks** (platform, browser family, TLS version drift detection)
- **Simple account graphing** (shared IP/device detection for mule pattern identification)
- **Privacy guardrails** (retention windows, regional data routing, consent flags for behavioral data)
- Feed risk scores into adaptive authentication layer (see PRD-027)
- Low cost, easy to store, easy to test
- No ML, no GPU, no complex behavioral models

### Non-Goals

- Machine learning-based risk models (see PRD-007B for future ML enhancement)
- Advanced behavioral biometrics (keystroke dynamics, mouse patterns)
- Full device fingerprinting (canvas, WebGL, audio fingerprinting)
- Graph database for fraud ring detection
- Real-time threat intelligence feed integration (future)
- A/B testing frameworks for detectors
- Hardware security module attestation

---

## 2. User Stories

**As a security engineer**
**I want to** continuously score session risk based on request metadata
**So that** I can detect account takeover attempts in real-time

**As a system operator**
**I want to** detect impossible travel patterns with ISP awareness
**So that** I can flag VPN-hopping attacks while allowing legitimate VPN users

**As a compliance officer**
**I want to** enforce privacy guardrails on behavioral data collection
**So that** we remain GDPR and HIPAA compliant

**As a developer**
**I want to** inspect payload anomalies (header tampering, replay attacks)
**So that** I can prevent API abuse and bot attacks

**As an admin**
**I want to** view shared device/IP usage patterns
**So that** I can identify account mule operations

---

## 3. Functional Requirements

### FR-1: Continuous Session Risk Scoring

**Scope:** All authenticated requests

**Description:** Lightweight rule-based scoring engine that evaluates each request and assigns a risk score (0-100) based on request metadata.

**Risk Factors:**

| Factor                        | Weight | Detection Logic                                     | Score Impact |
| ----------------------------- | ------ | --------------------------------------------------- | ------------ |
| **IP Change**                 | High   | IP differs from session creation IP                 | +20          |
| **User Agent Drift**          | Medium | UA string differs from session creation             | +15          |
| **Geolocation Shift**         | High   | Country/region change without impossible travel     | +10          |
| **High Failure Rate**         | High   | >5 failed operations in 10 minutes                  | +25          |
| **Spike in Activity**         | Medium | Request rate >200% of user baseline                 | +15          |
| **High Entropy Payload**      | Medium | Unusual characters in form fields                   | +10          |
| **Known Bad IP**              | High   | IP in abuse database (AbuseIPDB, etc.)              | +30          |
| **New Device (no history)**   | Low    | Device fingerprint never seen before                | +5           |
| **Shared Device Pattern**     | Medium | Device used by >5 users in 24h                      | +15          |
| **Clock Skew**                | Low    | Client clock differs from server by >5 minutes      | +5           |
| **Missing Security Headers**  | Low    | No CSRF token, no nonce, etc.                       | +5           |
| **Replay Detected**           | High   | Request signature matches recent request            | +40          |

**Risk Score Bands:**

- **0-20:** Low risk (allow)
- **21-50:** Medium risk (log, monitor)
- **51-75:** High risk (require step-up auth, see PRD-027)
- **76-100:** Critical risk (deny, soft-lock session, see PRD-027)

**Data Model:**

```go
type RiskScore struct {
    ID            string              `json:"id"`
    SessionID     string              `json:"session_id"`
    UserID        string              `json:"user_id"`
    Score         int                 `json:"score"`          // 0-100
    Factors       []RiskFactor        `json:"factors"`        // What contributed
    Timestamp     time.Time           `json:"timestamp"`
    RequestID     string              `json:"request_id"`
    IP            string              `json:"ip"`
    UserAgent     string              `json:"user_agent"`
    Geolocation   *GeoLocation        `json:"geolocation"`
}

type RiskFactor struct {
    Name        string  `json:"name"`
    Weight      int     `json:"weight"`
    Description string  `json:"description"`
}
```

**Business Logic:**

1. On each authenticated request, extract metadata (IP, UA, timestamp, payload)
2. Compare against session baseline (IP, UA, geo from session creation)
3. Check for anomalies (IP change, UA drift, geo shift)
4. Check recent failure count (from audit log)
5. Check request velocity (count requests in last 10 min)
6. Check payload entropy (form fields, headers)
7. Check IP reputation (local cache of abuse lists)
8. Check device sharing pattern (device -> user count)
9. Calculate composite risk score
10. Store RiskScore record
11. If score > threshold, trigger action (see PRD-027)
12. Return risk score in request context for downstream use

**Storage:**

- Redis for fast lookups: `risk:session:{session_id}:latest` → RiskScore (JSON)
- PostgreSQL for historical analysis: `risk_scores` table
- TTL: 90 days (compliance with privacy guardrails)

---

### FR-2: Impossible Travel Detection with ISP/ASN Awareness

**Scope:** Login and session creation endpoints

**Description:** Detect geographically impossible travel patterns using GeoIP + velocity thresholds, with ISP/ASN context to distinguish VPN use from actual travel.

**Algorithm:**

```
For each login attempt:
1. Extract IP from request
2. Lookup GeoIP coordinates (lat, lon) and ASN
3. Retrieve last known location for user
4. Calculate distance between locations (Haversine formula)
5. Calculate time elapsed since last login
6. Calculate velocity: distance / time
7. If velocity > threshold (e.g., 800 km/h):
   a. Check if new ISP/ASN is in user's VPN allowlist
   b. Check if ASN is known VPN provider (Cloudflare WARP, NordVPN, etc.)
   c. If yes → log but allow (user switched VPN endpoints)
   d. If no → flag as impossible travel, increase risk score by +40
8. Store current location as baseline for next check
```

**VPN Allowlist:**

Users can register trusted VPN providers via `/me/vpn-allowlist`:

```json
{
  "asn": [13335, 52048], // Cloudflare, VyprVPN
  "reason": "Work VPN"
}
```

**Thresholds:**

- **Impossible velocity:** >800 km/h (plane speed)
- **Suspicious velocity:** >200 km/h (high-speed train)

**Action:**

- Impossible velocity + no VPN match → Risk +40
- Suspicious velocity → Risk +15
- Emit audit event: `impossible_travel_detected`

**Data Model:**

```go
type TravelEvent struct {
    UserID        string
    SessionID     string
    FromLocation  GeoLocation
    ToLocation    GeoLocation
    Distance      float64 // kilometers
    Velocity      float64 // km/h
    TimeElapsed   time.Duration
    ASN           int
    ISP           string
    Flagged       bool
}

type GeoLocation struct {
    IP          string
    Country     string
    Region      string
    City        string
    Latitude    float64
    Longitude   float64
    ASN         int
    ISP         string
}
```

**Implementation:**

- Use MaxMind GeoIP2 database (free city-level accuracy)
- Use MaxMind ASN database for ISP detection
- Store last known location per user in Redis: `user:{user_id}:last_location`

---

### FR-3: Bot Detection & Abuse Countermeasures (Lightweight)

**Scope:** All public endpoints

**Description:** Simple bot detection using allow/deny lists, tarpitting, and optional WebAuthn challenge. No behavioral analysis.

#### FR-3.1: Good Bot Allowlist

**Purpose:** Allow known good bots (search engines, monitoring tools)

**List:**

- Googlebot (user-agent pattern + IP verification via DNS)
- Bingbot
- Site monitoring tools (Pingdom, UptimeRobot)
- Health check endpoints from load balancers

**Implementation:**

- Maintain allowlist in config file: `config/good_bots.yaml`
- Match user-agent regex patterns
- Verify IP via reverse DNS for search engines
- Bypass rate limits and risk scoring for good bots

**Example:**

```yaml
good_bots:
  - name: Googlebot
    user_agent_regex: "Googlebot"
    verify_dns: true
    dns_suffix: ".googlebot.com"
  - name: Internal Health Check
    user_agent_regex: "ELB-HealthChecker"
    ip_ranges: ["10.0.0.0/8"]
```

#### FR-3.2: Bad Bot Fingerprints

**Purpose:** Block known malicious bots (credential stuffing tools, scrapers)

**Signals:**

- User-agent in deny list (curl without custom UA, python-requests, etc.)
- Missing standard browser headers (Accept-Language, Accept-Encoding)
- Suspicious header order (non-standard TLS fingerprint)
- High request rate + low session diversity (same IP, many sessions)

**Action:**

- Immediate 403 Forbidden
- Add IP to temporary blocklist (1 hour)
- Emit audit event: `bad_bot_blocked`

**Deny List:**

```yaml
bad_bots:
  - user_agent_pattern: "python-requests"
  - user_agent_pattern: "curl"
  - user_agent_pattern: "scrapy"
  - missing_headers: ["Accept-Language", "Accept-Encoding"]
```

#### FR-3.3: Tarpitting

**Purpose:** Slow down suspicious traffic without outright blocking

**Triggers:**

- Risk score 51-75
- 3+ failed login attempts in 5 minutes
- Missing CSRF token (non-GET requests)

**Implementation:**

- Inject progressive delay before responding: 500ms → 1s → 2s → 5s
- Serve response normally but slowly
- Client experiences performance degradation, making automated attacks less efficient

**Example:**

```go
func TarpitMiddleware(riskScore int) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if riskScore > 50 {
            delay := time.Duration(riskScore-50) * 100 * time.Millisecond
            time.Sleep(delay)
        }
        next.ServeHTTP(w, r)
    })
}
```

#### FR-3.4: Optional WebAuthn Challenge

**Purpose:** Challenge high-risk requests with WebAuthn (if enrolled)

**Trigger:**

- Risk score >75 + user has WebAuthn enrolled

**Flow:**

1. Detect high-risk request
2. Check if user has WebAuthn credential
3. If yes, return 401 with `X-Challenge: webauthn`
4. Client re-submits request with WebAuthn assertion
5. Validate assertion, reduce risk score by -30

**Non-Goal:** This is optional. If WebAuthn not enrolled, fall back to PRD-027 adaptive auth.

---

### FR-4: Payload Anomaly Detection

**Scope:** All POST/PUT/PATCH endpoints

**Description:** Inspect request payloads for anomalies without complex ML models.

#### FR-4.1: Header Anomalies

**Checks:**

- **Missing security headers:** No `X-CSRF-Token`, no `Origin`, no `Referer`
- **Suspicious User-Agent:** Empty, too short (<10 chars), contains SQL keywords
- **Content-Type mismatch:** Body is JSON but Content-Type is `text/plain`
- **Duplicate headers:** Same header appears multiple times (attack vector)
- **Encoding anomalies:** Mixed encoding (UTF-8 + Latin-1)

**Action:**

- Each anomaly → Risk +5
- >3 anomalies → Risk +20
- Log to audit: `header_anomaly_detected`

#### FR-4.2: Form Field Entropy Checks

**Purpose:** Detect gibberish, injection attempts, base64-encoded payloads

**Algorithm:**

```
For each form field (string value):
1. Calculate Shannon entropy
2. If entropy > 4.5 (high randomness) → flag as suspicious
3. Check for SQL keywords (SELECT, DROP, UNION)
4. Check for script tags (<script>, onerror=)
5. Check for excessively long values (>1000 chars for name fields)
6. Check for base64 patterns (long alphanumeric + trailing =)
```

**Thresholds:**

- Entropy >4.5 → Risk +10
- SQL keyword → Risk +20 (potential SQLi)
- Script tag → Risk +20 (potential XSS)
- Overlength field → Risk +5

**Example:**

```go
func calculateEntropy(s string) float64 {
    if len(s) == 0 {
        return 0
    }
    freq := make(map[rune]int)
    for _, c := range s {
        freq[c]++
    }
    var entropy float64
    for _, count := range freq {
        p := float64(count) / float64(len(s))
        entropy -= p * math.Log2(p)
    }
    return entropy
}
```

#### FR-4.3: Replay Detection

**Purpose:** Prevent replay attacks (reusing valid signed requests)

**Implementation:**

1. Client includes nonce in request: `X-Request-Nonce: {uuid}`
2. Server checks nonce against Redis set: `nonce:{client_id}:{nonce}`
3. If nonce exists → replay detected → 403
4. If new → store nonce with TTL (5 minutes)

**Nonce Format:**

- UUID v4
- Included in JWT claims or as custom header
- Server-side set: `nonces` (Redis set with TTL)

**Action:**

- Replay detected → Risk +40, deny request, emit `replay_attack_detected`

#### FR-4.4: Clock Skew Detection

**Purpose:** Detect clients with suspicious time drift (possible attack setup)

**Implementation:**

1. Client includes timestamp in request: `X-Client-Timestamp: {unix_ms}`
2. Server compares with server time
3. If diff >5 minutes → flag as suspicious

**Action:**

- Clock skew >5 min → Risk +5
- Clock skew >30 min → Risk +15 (possible replay attempt with old token)

---

### FR-5: Device Consistency Checks (Not Full Fingerprinting)

**Scope:** Authenticated sessions

**Description:** Collect stable device signals and detect drift during session lifetime. Avoid invasive fingerprinting (no canvas, no WebGL, no audio).

**Collected Signals:**

| Signal            | Example                  | Change Impact |
| ----------------- | ------------------------ | ------------- |
| **Platform**      | macOS, Windows, Linux    | High          |
| **Browser Family**| Chrome, Firefox, Safari  | High          |
| **Browser Version Major** | 120, 119, 121    | Low           |
| **TLS Version**   | TLS 1.3, TLS 1.2         | Medium        |
| **Screen Width**  | 1920, 1440, 2560         | Low           |
| **Timezone**      | America/New_York, UTC    | Medium        |

**Device Fingerprint:**

```go
type DeviceFingerprint struct {
    Platform       string `json:"platform"`       // "MacIntel", "Win32"
    BrowserFamily  string `json:"browser_family"` // "Chrome", "Firefox"
    BrowserVersion string `json:"browser_version"`// "120.0"
    TLSVersion     string `json:"tls_version"`    // "TLS 1.3"
    ScreenWidth    int    `json:"screen_width"`
    Timezone       string `json:"timezone"`
    Hash           string `json:"hash"`           // SHA256 of above
}
```

**Drift Detection:**

On each request:

1. Extract current device fingerprint
2. Compare with session baseline (stored at session creation)
3. Calculate drift score:
   - Platform change → Risk +20 (high)
   - Browser family change → Risk +15 (high)
   - TLS version change → Risk +10 (medium)
   - Timezone change → Risk +5 (low)
   - Screen width change → Risk +2 (low)

**Action:**

- Total drift score >20 → Risk +20, flag as `device_drift_detected`
- Emit audit event with details

**Storage:**

- Redis: `device:{session_id}:baseline` → DeviceFingerprint (JSON)

**Non-Goal:**

- No hardware attestation
- No canvas fingerprinting
- No font enumeration
- No WebGL/Audio fingerprinting

---

### FR-6: Simple Account Graphing (Shared IP/Device Detection)

**Scope:** All authenticated users

**Description:** Lightweight graph data structure to detect shared devices/IPs (mule account patterns) without complex graph database.

**Data Structures:**

```
Redis Keys:
- graph:user:{user_id}:devices → Set of device hashes
- graph:device:{device_hash}:users → Set of user IDs
- graph:ip:{ip}:users → Set of user IDs (24h TTL)
```

**Algorithm:**

On each login:

1. Extract user ID, device hash, IP
2. Add to Redis sets:
   - `SADD graph:user:{user_id}:devices {device_hash}`
   - `SADD graph:device:{device_hash}:users {user_id}`
   - `SADD graph:ip:{ip}:users {user_id}` (with 24h TTL)
3. Check device sharing:
   - `count = SCARD graph:device:{device_hash}:users`
   - If count >5 → Shared device pattern detected → Risk +15
4. Check IP sharing:
   - `count = SCARD graph:ip:{ip}:users`
   - If count >10 → Shared IP pattern (mule farm) → Risk +20

**Mule Pattern Detection:**

- Device used by >5 users in 24h → Potential mule device
- IP used by >10 users in 24h → Potential mule farm
- User has >3 devices in 7 days → Potential mule operator

**Action:**

- Mule pattern detected → Risk +20, emit `mule_pattern_detected`
- Admin review queue: `/admin/mule-review`

**Allowlist:**

For shared office IPs, add to allowlist:

```json
{
  "ip": "203.0.113.45",
  "reason": "Corporate office"
}
```

**Storage:**

- Redis sets (fast set operations)
- PostgreSQL for audit/historical analysis

---

### FR-7: Privacy Guardrails

**Description:** Ensure behavioral data collection complies with GDPR, HIPAA, CCPA.

#### FR-7.1: Retention Windows

**Policy:**

| Data Type               | Retention Period | Justification                |
| ----------------------- | ---------------- | ---------------------------- |
| **Risk Scores**         | 90 days          | Fraud analysis window        |
| **Device Fingerprints** | 1 year           | Session consistency checking |
| **Travel Events**       | 90 days          | Impossible travel detection  |
| **IP Graph Data**       | 24 hours         | Mule detection (rolling)     |
| **Audit Logs**          | 7 years          | Compliance requirement       |

**Implementation:**

- PostgreSQL: Set retention policies with pg_cron
- Redis: Use TTL on all keys
- Auto-deletion jobs: Daily cleanup of expired records

#### FR-7.2: Regional Data Routing

**Purpose:** Keep EU user data in EU, US data in US (GDPR Article 44-49)

**Implementation:**

- User profile includes `region` field (derived from signup IP)
- Risk scoring data stored in regional PostgreSQL instance
- Redis cluster partitioned by region
- Cross-region queries disabled (fail-safe)

**Regions:**

- `eu` → Frankfurt datacenter
- `us` → Virginia datacenter
- `apac` → Singapore datacenter

#### FR-7.3: Consent Flags for Behavioral Data

**Purpose:** Allow users to opt out of behavioral analysis (GDPR right to object)

**Consent Purpose:** `security_analytics` (new, add to PRD-002)

**Flow:**

1. User can grant/revoke via `/auth/consent`
2. If revoked:
   - Risk scoring still occurs (security necessity) but no storage
   - Device fingerprinting disabled
   - Account graphing disabled
3. If granted:
   - Full feature set enabled
   - Data stored according to retention policy

**Fallback:**

- Users without consent → Risk scoring in-memory only (not persisted)
- Higher false positive rate (acceptable trade-off)

**Audit:**

- Consent grants/revocations logged (PRD-002)

---

## 4. Technical Requirements

### TR-1: Risk Scoring Engine

**Location:** `internal/security/riskscore/engine.go`

```go
type RiskEngine interface {
    Score(ctx context.Context, req *Request) (*RiskScore, error)
    GetSessionRisk(ctx context.Context, sessionID string) (*RiskScore, error)
}

type Request struct {
    SessionID     string
    UserID        string
    IP            string
    UserAgent     string
    Timestamp     time.Time
    Payload       map[string]interface{}
    Headers       http.Header
    Geolocation   *GeoLocation
    Device        *DeviceFingerprint
}

type DefaultRiskEngine struct {
    geoip         *geoip2.Reader
    asndb         *geoip2.Reader
    redis         *redis.Client
    db            *sql.DB
    detectors     []Detector
}

type Detector interface {
    Name() string
    Detect(ctx context.Context, req *Request) (score int, factors []RiskFactor, error)
}

// Detectors:
// - IPChangeDetector
// - UADriftDetector
// - ImpossibleTravelDetector
// - VelocityDetector
// - PayloadAnomalyDetector
// - DeviceDriftDetector
// - AccountGraphDetector
// - ReplayDetector
```

### TR-2: GeoIP Integration

**Library:** MaxMind GeoIP2

**Files:**

- `GeoLite2-City.mmdb` (free, update weekly)
- `GeoLite2-ASN.mmdb` (free, update weekly)

**Deployment:**

- Mount as read-only volume in Docker
- Update via cron job (weekly)

**Usage:**

```go
import "github.com/oschwald/geoip2-golang"

db, _ := geoip2.Open("GeoLite2-City.mmdb")
defer db.Close()

record, _ := db.City(net.ParseIP("203.0.113.1"))
fmt.Println(record.City.Names["en"]) // "London"
fmt.Println(record.Location.Latitude) // 51.5074
```

### TR-3: Data Models

**PostgreSQL Schema:**

```sql
CREATE TABLE risk_scores (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL,
    user_id UUID NOT NULL,
    score INT NOT NULL,
    factors JSONB,
    timestamp TIMESTAMPTZ NOT NULL,
    request_id TEXT,
    ip INET,
    user_agent TEXT,
    geolocation JSONB,
    region TEXT,
    CONSTRAINT risk_scores_retention CHECK (timestamp > NOW() - INTERVAL '90 days')
);

CREATE INDEX idx_risk_scores_session ON risk_scores(session_id, timestamp DESC);
CREATE INDEX idx_risk_scores_user ON risk_scores(user_id, timestamp DESC);

CREATE TABLE travel_events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    from_location JSONB,
    to_location JSONB,
    distance_km FLOAT,
    velocity_kmh FLOAT,
    time_elapsed_sec INT,
    asn INT,
    isp TEXT,
    flagged BOOLEAN,
    timestamp TIMESTAMPTZ NOT NULL,
    CONSTRAINT travel_events_retention CHECK (timestamp > NOW() - INTERVAL '90 days')
);

CREATE TABLE device_fingerprints (
    hash TEXT PRIMARY KEY,
    platform TEXT,
    browser_family TEXT,
    browser_version TEXT,
    tls_version TEXT,
    screen_width INT,
    timezone TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);
```

**Redis Keys:**

```
# Latest risk score per session
risk:session:{session_id}:latest → JSON (TTL: 24h)

# User baseline location
user:{user_id}:last_location → JSON (TTL: 90d)

# Device baseline per session
device:{session_id}:baseline → JSON (TTL: session lifetime)

# Nonce replay protection
nonce:{client_id}:{nonce} → 1 (TTL: 5min)

# Account graph
graph:user:{user_id}:devices → Set (TTL: 1 year)
graph:device:{device_hash}:users → Set (TTL: 1 year)
graph:ip:{ip}:users → Set (TTL: 24h)
```

### TR-4: Configuration

**Location:** `internal/security/config/fraud_detection.yaml`

```yaml
fraud_detection:
  enabled: true

  risk_scoring:
    enabled: true
    thresholds:
      low: 20
      medium: 50
      high: 75
      critical: 90

  impossible_travel:
    enabled: true
    velocity_threshold_kmh: 800
    suspicious_velocity_kmh: 200
    vpn_allowlist_enabled: true

  bot_detection:
    enabled: true
    good_bots_file: "config/good_bots.yaml"
    bad_bots_file: "config/bad_bots.yaml"
    tarpitting_enabled: true

  payload_anomalies:
    enabled: true
    entropy_threshold: 4.5
    max_field_length: 1000
    replay_detection: true
    clock_skew_tolerance_min: 5

  device_consistency:
    enabled: true
    drift_threshold: 20

  account_graphing:
    enabled: true
    device_sharing_threshold: 5
    ip_sharing_threshold: 10

  privacy:
    retention_days: 90
    regional_routing: true
    require_consent: false # Security is lawful basis under GDPR
```

### TR-5: Middleware Integration

**Location:** `internal/transport/http/middleware/risk_scoring.go`

```go
func RiskScoringMiddleware(engine RiskEngine) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Skip for good bots
            if isGoodBot(r) {
                next.ServeHTTP(w, r)
                return
            }

            // Extract session/user from context
            sessionID := getSessionID(r.Context())
            userID := getUserID(r.Context())

            // Build risk request
            req := &Request{
                SessionID: sessionID,
                UserID:    userID,
                IP:        extractIP(r),
                UserAgent: r.UserAgent(),
                Timestamp: time.Now(),
                Headers:   r.Header,
            }

            // Score risk
            riskScore, err := engine.Score(r.Context(), req)
            if err != nil {
                // Log error but don't block request (fail open)
                logger.Error("risk scoring failed", "error", err)
            }

            // Inject risk score into context
            ctx := withRiskScore(r.Context(), riskScore)

            // Check if risk warrants action (see PRD-027)
            if riskScore.Score > 75 {
                // High risk - trigger adaptive auth
                // (handled by PRD-027 middleware)
            }

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### TR-6: SQL Query Patterns for Fraud Analytics

**Objective:** Demonstrate intermediate-to-advanced SQL capabilities for fraud detection and security intelligence.

**Query Patterns Required:**

- **Window Functions for Velocity Detection:** Use sliding windows to detect request bursts:
  ```sql
  SELECT user_id, session_id, timestamp,
         COUNT(*) OVER (
           PARTITION BY user_id
           ORDER BY timestamp
           RANGE BETWEEN INTERVAL '10 minutes' PRECEDING AND CURRENT ROW
         ) AS requests_last_10min,
         LAG(timestamp) OVER (PARTITION BY user_id ORDER BY timestamp) AS prev_request,
         timestamp - LAG(timestamp) OVER (PARTITION BY user_id ORDER BY timestamp) AS time_gap
  FROM risk_scores
  WHERE timestamp > NOW() - INTERVAL '1 hour'
  HAVING COUNT(*) OVER (...) > 50;  -- Velocity threshold
  ```

- **Self-Join for Impossible Travel Detection:**
  ```sql
  SELECT t1.user_id, t1.id AS trip1_id, t2.id AS trip2_id,
         t1.to_location->>'city' AS from_city,
         t2.to_location->>'city' AS to_city,
         ST_Distance(
           ST_Point(t1.to_location->>'lon', t1.to_location->>'lat'),
           ST_Point(t2.to_location->>'lon', t2.to_location->>'lat')
         ) / EXTRACT(EPOCH FROM (t2.timestamp - t1.timestamp)) * 3.6 AS velocity_kmh
  FROM travel_events t1
  JOIN travel_events t2
    ON t1.user_id = t2.user_id
    AND t2.timestamp > t1.timestamp
    AND t2.timestamp < t1.timestamp + INTERVAL '4 hours'
  WHERE velocity_kmh > 800;  -- Impossible velocity threshold
  ```

- **CTE for Multi-Hop Account Graph (Mule Pattern):**
  ```sql
  WITH RECURSIVE device_network AS (
    -- Base: Start with suspicious device
    SELECT device_hash, user_id, 1 AS hop
    FROM device_fingerprints df
    JOIN sessions s ON df.hash = s.device_hash
    WHERE df.hash = :suspicious_device

    UNION ALL

    -- Recursive: Find connected devices through shared users
    SELECT s2.device_hash, s2.user_id, dn.hop + 1
    FROM device_network dn
    JOIN sessions s1 ON dn.user_id = s1.user_id
    JOIN sessions s2 ON s1.device_hash = s2.device_hash
    WHERE dn.hop < 3  -- Max 3 hops
  )
  SELECT device_hash, COUNT(DISTINCT user_id) AS user_count
  FROM device_network
  GROUP BY device_hash
  HAVING COUNT(DISTINCT user_id) > 5;  -- Mule threshold
  ```

- **Aggregate Functions for Risk Score Distribution:**
  ```sql
  SELECT
    DATE_TRUNC('hour', timestamp) AS hour,
    COUNT(*) AS total_requests,
    AVG(score) AS avg_score,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY score) AS p95_score,
    SUM(CASE WHEN score >= 75 THEN 1 ELSE 0 END) AS high_risk_count,
    COUNT(*) FILTER (WHERE factors @> '[{"name": "impossible_travel"}]') AS travel_anomalies
  FROM risk_scores
  WHERE timestamp > NOW() - INTERVAL '24 hours'
  GROUP BY DATE_TRUNC('hour', timestamp)
  HAVING SUM(CASE WHEN score >= 75 THEN 1 ELSE 0 END) > 10;
  ```

- **Semi-Join for IP Reputation Check:**
  ```sql
  -- Find risky requests from known bad IPs
  SELECT rs.*
  FROM risk_scores rs
  WHERE EXISTS (
    SELECT 1 FROM ip_reputation ir
    WHERE ir.ip = rs.ip
      AND ir.reputation = 'malicious'
      AND ir.last_seen > NOW() - INTERVAL '7 days'
  );

  -- Anti-join: Find unscored sessions (gaps in coverage)
  SELECT s.id, s.user_id, s.created_at
  FROM sessions s
  WHERE NOT EXISTS (
    SELECT 1 FROM risk_scores rs
    WHERE rs.session_id = s.id
  )
  AND s.created_at > NOW() - INTERVAL '1 hour';
  ```

- **Materialized View for Hot Risk Signals:**
  ```sql
  CREATE MATERIALIZED VIEW hourly_risk_summary AS
  SELECT
    DATE_TRUNC('hour', timestamp) AS hour,
    user_id,
    COUNT(*) AS request_count,
    AVG(score) AS avg_score,
    MAX(score) AS max_score,
    array_agg(DISTINCT factors->>'name') AS triggered_detectors
  FROM risk_scores, jsonb_array_elements(factors) AS factors
  WHERE timestamp > NOW() - INTERVAL '24 hours'
  GROUP BY DATE_TRUNC('hour', timestamp), user_id
  WITH DATA;

  CREATE INDEX ON hourly_risk_summary (hour, max_score DESC);
  REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_risk_summary;
  ```

**Database Design:**

- **Partitioning:** `risk_scores` partitioned by week for efficient pruning; use `pg_partman` for automation
- **JSONB Indexes:** GIN index on `factors` for detector-based queries
- **Probabilistic Data Structures:**
  - Count-Min Sketch for IP velocity estimates (false positive rate < 1%)
  - Bloom filter for nonce replay detection (10M items, 0.1% FP)
- **Star Schema for Analytics:** Dimension tables for `users`, `devices`, `locations`; fact table for `risk_scores`

---

**SQL Indexing Enhancements (from "Use The Index, Luke"):**

**Anti-Join for Orphaned Token Detection (Fraud Signal):**

```sql
-- WHY THIS MATTERS: Orphaned tokens (tokens without valid sessions) may indicate
-- session hijacking or credential theft. Anti-join efficiently finds these anomalies.

-- Anti-join: Find tokens without valid sessions
SELECT t.id, t.user_id, t.created_at
FROM refresh_tokens t
WHERE NOT EXISTS (
    SELECT 1 FROM sessions s
    WHERE s.id = t.session_id
      AND s.status = 'active'
);
-- Orphaned tokens are a strong fraud signal

-- Index to support anti-join:
CREATE INDEX idx_tokens_session ON refresh_tokens (session_id);
CREATE INDEX idx_sessions_active ON sessions (id) WHERE status = 'active';

-- EXPLAIN should show:
-- "Nested Loop Anti Join" with "Index Scan" on both tables
-- NOT: "Hash Anti Join" with sequential scans
```

**Window Function for Token Refresh Velocity (Fraud Indicator):**

```sql
-- WHY THIS MATTERS: Abnormal token refresh rate indicates credential abuse.
-- Normal users refresh tokens occasionally; attackers refresh rapidly.

SELECT user_id, token_id, refreshed_at,
       COUNT(*) OVER (
         PARTITION BY user_id
         ORDER BY refreshed_at
         RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
       ) AS refreshes_last_5min,
       COUNT(*) OVER (
         PARTITION BY user_id
         ORDER BY refreshed_at
         RANGE BETWEEN INTERVAL '1 hour' PRECEDING AND CURRENT ROW
       ) AS refreshes_last_hour
FROM token_refresh_log
WHERE refreshes_last_5min > 10;  -- Velocity threshold

-- Index for token velocity queries:
CREATE INDEX idx_token_refresh_user_time ON token_refresh_log (user_id, refreshed_at);

-- High velocity (>10 refreshes in 5 min) → high fraud probability
-- Combined with IP change → very high fraud probability
```

**NULL Handling for Revocation Timestamps:**

```sql
-- WHY THIS MATTERS: revoked_at IS NULL indicates active tokens.
-- Standard B-Tree indexes don't efficiently handle NULL IS NULL queries.
-- Use partial indexes for active/revoked token filtering.

-- Partial index for active (unrevoked) tokens:
CREATE INDEX idx_tokens_active ON refresh_tokens (user_id, token_hash)
  WHERE revoked_at IS NULL;

-- Query for active tokens (uses partial index):
SELECT * FROM refresh_tokens
WHERE user_id = :uid AND revoked_at IS NULL;

-- Partial index for revoked tokens (fraud investigation):
CREATE INDEX idx_tokens_revoked ON refresh_tokens (user_id, revoked_at)
  WHERE revoked_at IS NOT NULL;

-- Query for recently revoked tokens:
SELECT * FROM refresh_tokens
WHERE user_id = :uid
  AND revoked_at IS NOT NULL
  AND revoked_at > NOW() - INTERVAL '7 days';

-- EXPLAIN should show: "Index Scan" on partial index
-- Index size: Active index much smaller than full index
```

**Hash Join for IP Reputation Lookup:**

```sql
-- WHY THIS MATTERS: IP reputation checks compare risk_scores against ip_reputation.
-- Hash Join is efficient when ip_reputation table fits in memory.

-- Enable hash join for reputation lookup:
EXPLAIN ANALYZE
SELECT rs.*, ir.reputation, ir.threat_type
FROM risk_scores rs
JOIN ip_reputation ir ON rs.ip = ir.ip
WHERE rs.timestamp > NOW() - INTERVAL '1 hour'
  AND ir.reputation = 'malicious';

-- PostgreSQL chooses Hash Join when:
-- 1. Inner table (ip_reputation) fits in work_mem
-- 2. No usable index on join column
-- 3. Large result expected

-- For small ip_reputation with index, Nested Loop is fine:
CREATE INDEX idx_ip_reputation ON ip_reputation (ip) WHERE reputation = 'malicious';
-- This enables Nested Loop with index scan on reputation check
```

---

**Acceptance Criteria (SQL):**
- [ ] Velocity detection uses window functions with sliding ranges
- [ ] Impossible travel detection uses self-joins with distance calculations
- [ ] Account graphing uses recursive CTEs with hop limits
- [ ] Risk distribution uses aggregates with PERCENTILE_CONT
- [ ] IP reputation uses semi-joins (EXISTS) for efficient filtering
- [ ] Materialized views pre-aggregate hot signals with scheduled refresh
- [ ] All queries validated with `EXPLAIN ANALYZE` showing <50ms execution
- [ ] **NEW:** Orphaned token detection uses anti-join with appropriate indexes
- [ ] **NEW:** Token refresh velocity uses window functions with RANGE clause
- [ ] **NEW:** Active/revoked tokens use partial indexes for NULL handling
- [ ] **NEW:** IP reputation lookup uses appropriate join strategy (Hash/Nested Loop)

---

## 5. Observability Requirements

### Logging

**Events to Log:**

- `risk_score_calculated` (info) - Every request
- `impossible_travel_detected` (warning) - Travel anomaly
- `bad_bot_blocked` (warning) - Bot denied
- `replay_attack_detected` (alert) - Replay attempt
- `mule_pattern_detected` (alert) - Account graphing hit
- `device_drift_detected` (warning) - Device changed mid-session
- `header_anomaly_detected` (info) - Payload anomaly

**Log Format:**

```json
{
  "timestamp": "2025-12-12T10:30:00Z",
  "level": "warning",
  "event": "impossible_travel_detected",
  "user_id": "user_abc123",
  "session_id": "sess_xyz789",
  "risk_score": 65,
  "details": {
    "from_city": "New York",
    "to_city": "London",
    "velocity_kmh": 1200,
    "distance_km": 5570
  }
}
```

### Metrics

**Prometheus Metrics:**

```
# Counter: Total risk scores calculated
fraud_risk_scores_total{result="low|medium|high|critical"}

# Histogram: Risk score distribution
fraud_risk_score_value (buckets: 0, 20, 50, 75, 90, 100)

# Counter: Detector triggers
fraud_detector_triggered_total{detector="impossible_travel|bot|replay|..."}

# Counter: Blocked requests
fraud_requests_blocked_total{reason="bot|replay|high_risk"}

# Gauge: Current high-risk sessions
fraud_high_risk_sessions

# Histogram: Risk scoring latency
fraud_risk_scoring_duration_seconds
```

### Dashboards

**Grafana Dashboard Panels:**

1. Risk Score Heatmap (users over time)
2. Top High-Risk Users (table)
3. Detector Trigger Rate (stacked area chart)
4. Impossible Travel Events (world map)
5. Bot Blocking Rate (time series)
6. Payload Anomaly Types (pie chart)

---

## 6. Testing Requirements

### Unit Tests

- [x] Test risk scoring engine with mock detectors
- [x] Test impossible travel calculation (Haversine distance)
- [x] Test payload entropy calculation
- [x] Test device fingerprint drift detection
- [x] Test account graph set operations
- [x] Test replay nonce storage/checking
- [x] Test privacy retention policies

### Integration Tests

- [ ] End-to-end risk scoring on real request
- [ ] Impossible travel with GeoIP database
- [ ] Bot detection with good/bad bot lists
- [ ] Payload anomaly with crafted malicious payloads
- [ ] Device drift detection across multiple requests
- [ ] Account graphing with multiple users/devices

### Load Tests

- [ ] Risk scoring latency <20ms p99
- [ ] GeoIP lookup latency <5ms
- [ ] Redis graph operations <10ms
- [ ] Scoring throughput >10k req/sec

### Security Tests

- [ ] Replay attack prevention (reuse nonce)
- [ ] SQL injection detection (payload entropy)
- [ ] XSS detection (script tag entropy)
- [ ] Header injection (duplicate headers)
- [ ] Clock skew bypass attempts

---

## 7. Implementation Steps

### Phase 1: Foundation (Week 1)

1. Setup GeoIP databases (MaxMind)
2. Implement RiskEngine interface
3. Create PostgreSQL schema
4. Setup Redis for graph data
5. Build basic risk scoring (IP change, UA drift)

### Phase 2: Detectors (Week 2)

1. Implement ImpossibleTravelDetector
2. Implement PayloadAnomalyDetector
3. Implement DeviceDriftDetector
4. Implement BotDetector (good/bad lists)
5. Implement ReplayDetector

### Phase 3: Account Graphing (Week 3)

1. Implement Redis graph operations
2. Build mule pattern detection
3. Create admin review UI (extend PRD-026)
4. Add allowlist management

### Phase 4: Privacy & Compliance (Week 4)

1. Implement retention policies (pg_cron jobs)
2. Setup regional data routing
3. Add consent integration (PRD-002)
4. Document privacy guarantees

### Phase 5: Integration & Testing (Week 5)

1. Integrate middleware into router
2. Connect to adaptive auth (PRD-027)
3. Load testing and optimization
4. Security testing (penetration test)

---

## 8. Acceptance Criteria

- [ ] Risk scoring active on all authenticated requests
- [ ] Impossible travel detected with <1% false positive rate
- [ ] Bot detection blocks known bad bots, allows good bots
- [ ] Payload anomalies detected (SQL injection, XSS attempts)
- [ ] Device drift triggers alerts for mid-session changes
- [ ] Account graphing identifies mule patterns (>5 users per device)
- [ ] Privacy retention policies auto-delete data after 90 days
- [ ] Regional data routing enforced (EU data stays in EU)
- [ ] Risk scores feed into adaptive auth (PRD-027)
- [ ] Metrics and dashboards operational (Grafana)
- [ ] Latency <20ms p99 for risk scoring
- [ ] Code passes security review
- [ ] Feature store includes Count-Min Sketch/Bloom filters for velocity checks with documented false-positive bounds
- [ ] Materialized views indexed for hot risk signals with EXPLAIN evidence under load

---

## 9. Dependencies & Blockers

### Dependencies

- PRD-001: Authentication (session/user extraction)
- PRD-005B: Cerbos (future policy integration)
- PRD-017: Rate Limiting (complementary abuse prevention)
- PRD-021: MFA (step-up authentication fallback)

**External Libraries:**

- MaxMind GeoIP2 (free tier)
- Redis (already in stack)
- PostgreSQL (already in stack)

### Potential Blockers

- GeoIP database updates (require manual process, automate with cron)
- VPN detection accuracy (ASN database coverage)
- Privacy legal review (GDPR compliance confirmation)

---

## 10. Future Enhancements (Out of Scope)

- Machine learning-based risk models (see PRD-007B)
- Graph database for complex fraud rings (Neo4j)
- Real-time threat intelligence feeds (AbuseIPDB, Shodan)
- Behavioral biometrics (keystroke dynamics)
- Advanced device fingerprinting (canvas, WebGL)
- Federated fraud data sharing (consortium model)
- A/B testing framework for detectors

---

## 11. Open Questions

1. **GeoIP Update Frequency:** Weekly sufficient or need daily?
   - **Recommendation:** Weekly for city DB, monthly for ASN DB

2. **VPN Detection Accuracy:** How to handle corporate VPNs?
   - **Recommendation:** User-managed VPN allowlist + manual review

3. **False Positive Tolerance:** What's acceptable rate?
   - **Recommendation:** <1% for impossible travel, <5% for bot detection

4. **Regional Data Routing:** Do we need China-specific instance?
   - **Recommendation:** Defer until we have Chinese users

5. **Consent Requirement:** Is security analytics exempt under GDPR?
   - **Recommendation:** Yes (legitimate interest), but offer opt-out with reduced features

---

## 12. References

- [OWASP Fraud Detection](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [MaxMind GeoIP2](https://dev.maxmind.com/geoip/geoip2/geolite2/)
- [Haversine Distance Formula](https://en.wikipedia.org/wiki/Haversine_formula)
- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [GDPR Article 6(1)(f) - Legitimate Interest](https://gdpr-info.eu/art-6-gdpr/)

---

## Revision History

| Version | Date       | Author       | Changes                                                                                                           |
| ------- | ---------- | ------------ | ----------------------------------------------------------------------------------------------------------------- |
| 2.3     | 2025-12-21 | Engineering  | Enhanced TR-6: Added anti-joins for orphaned tokens, token velocity, NULL handling, hash joins                    |
| 2.2     | 2025-12-21 | Engineering  | Added TR-6: SQL Query Patterns (window functions, self-joins, recursive CTEs, aggregates, semi/anti-joins, star schema) |
| 2.1     | 2025-12-18 | Security Eng | Added DSA/SQL requirements (Count-Min/Bloom velocity checks, materialized views with EXPLAIN)                    |
| 2.0     | 2025-12-12 | Engineering  | Comprehensive expansion with rule-based fraud detection (9 features): continuous risk scoring, impossible travel, |
|         |            |              | bot detection, payload anomaly, device consistency, account graphing, privacy guardrails                         |
| 1.0     | 2025-12-12 | Product Team | Initial skeletal PRD                                                                                              |
