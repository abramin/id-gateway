# PRD-032: Privacy-Preserving Analytics

**Status:** Draft
**Priority:** P2 (Strategic)
**Owner:** Engineering Team
**Dependencies:** PRD-006 (Audit & Compliance), PRD-010 (Zero-Knowledge Proofs)

---

## 1. Overview

### Problem Statement

Businesses need analytics about their users to make informed decisions, but accessing individual user data creates privacy and compliance risks:

- **Privacy risk:** Raw data access exposes PII
- **Compliance risk:** GDPR requires data minimization
- **Trust risk:** Users don't want their data analyzed without consent
- **Security risk:** Centralized data access is an attack target

### Goals

- Enable **aggregate analytics without individual PII access**
- Implement **differential privacy** for query results
- Provide **query audit trail** showing who asked what
- Give users **transparency** into what queries touched their data
- Support **privacy budget** limiting total information disclosure

### Non-Goals

- Real-time analytics or streaming queries
- Machine learning model training
- Individual user behavior tracking
- Visualization or dashboarding UI

---

## 2. User Stories

**As a** business analyst
**I want to** get aggregate statistics about users
**So that** I can make data-driven decisions

**As a** compliance officer
**I want to** see all analytics queries that were run
**So that** I can audit data access patterns

**As a** user
**I want to** know what aggregate queries included my data
**So that** I understand how my data is used

**As a** privacy engineer
**I want to** enforce differential privacy on all queries
**So that** individual users can't be identified from results

---

## 3. Functional Requirements

### FR-1: Run Privacy-Preserving Query

**Endpoint:** `POST /analytics/query`

**Description:** Execute an aggregate query with differential privacy noise.

**Input:**
```json
{
  "query": {
    "type": "aggregate",
    "metrics": ["count", "avg_age", "verification_rate"],
    "filters": {
      "created_after": "2025-01-01",
      "verification_status": "verified"
    },
    "group_by": ["country"]
  },
  "privacy": {
    "epsilon": 1.0,
    "mechanism": "laplace"
  }
}
```

**Output (Success - 200):**
```json
{
  "query_id": "q_abc123",
  "results": [
    {
      "country": "US",
      "count": 1247,
      "avg_age": 34.2,
      "verification_rate": 0.78,
      "noise_applied": true
    },
    {
      "country": "UK",
      "count": 892,
      "avg_age": 31.8,
      "verification_rate": 0.82,
      "noise_applied": true
    }
  ],
  "metadata": {
    "epsilon_used": 1.0,
    "privacy_budget_remaining": 4.0,
    "min_group_size": 100,
    "suppressed_groups": 3
  }
}
```

### FR-2: Available Query Types

**Supported Aggregations:**
| Function | Description | Privacy Notes |
|----------|-------------|---------------|
| `count` | Count of records | Laplace noise added |
| `sum` | Sum of numeric field | Bounded sensitivity |
| `avg` | Average of numeric field | Derived from sum/count |
| `min`/`max` | Range statistics | Suppressed if group too small |
| `percentile` | Distribution percentiles | Requires larger epsilon |
| `distinct_count` | Unique value count | Uses HyperLogLog + noise |

### FR-3: Query Audit Trail

**Endpoint:** `GET /admin/analytics/audit`

**Output (Success - 200):**
```json
{
  "queries": [
    {
      "query_id": "q_abc123",
      "queried_by": "analyst@example.com",
      "query_type": "aggregate",
      "metrics": ["count", "avg_age"],
      "filters_applied": true,
      "epsilon_used": 1.0,
      "rows_touched": 15234,
      "timestamp": "2025-12-17T10:00:00Z"
    }
  ],
  "total_queries": 47,
  "total_epsilon_used": 23.5
}
```

### FR-4: User Transparency

**Endpoint:** `GET /me/analytics/usage`

**Description:** User sees which queries included their data.

**Output (Success - 200):**
```json
{
  "queries_involving_you": [
    {
      "query_id": "q_abc123",
      "query_date": "2025-12-17",
      "query_type": "aggregate",
      "purpose": "user_demographics",
      "your_data_fields": ["age_range", "country", "verification_status"],
      "result_type": "aggregate_only"
    }
  ],
  "total_queries": 12,
  "period": "last_90_days"
}
```

### FR-5: Privacy Budget Management

**Endpoint:** `GET /admin/analytics/budget`

**Output (Success - 200):**
```json
{
  "tenant_id": "tenant_123",
  "budget": {
    "total_epsilon": 10.0,
    "used_epsilon": 6.5,
    "remaining_epsilon": 3.5,
    "reset_at": "2026-01-01T00:00:00Z"
  },
  "usage_by_analyst": [
    {"analyst": "alice@example.com", "epsilon_used": 4.0},
    {"analyst": "bob@example.com", "epsilon_used": 2.5}
  ]
}
```

---

## 4. Technical Requirements

### TR-1: Differential Privacy Implementation

**Laplace Mechanism:**
```
noisy_result = true_result + Laplace(0, sensitivity/epsilon)
```

**Parameters:**
- **Epsilon (ε):** Privacy loss parameter (lower = more privacy)
- **Sensitivity:** Maximum change from adding/removing one record
- **Minimum group size:** Suppress results for groups < threshold

### TR-2: Query Restrictions

- Only aggregate queries allowed (no `SELECT *`)
- Filters cannot be too specific (min 100 matching records)
- Group-by results suppressed if group < 50 records
- No queries returning individual identifiers

### TR-3: Data Model

```
analytics_queries
├── query_id (PK)
├── tenant_id
├── queried_by
├── query_definition (JSONB)
├── epsilon_used
├── rows_touched
├── result_hash
├── timestamp
└── status

analytics_budget
├── tenant_id (PK)
├── total_epsilon
├── used_epsilon
├── reset_period
└── last_reset_at

user_query_touchpoints
├── user_id
├── query_id
├── fields_included []
├── timestamp
└── (no result data stored)
```

### TR-4: Query DSL

Restricted query language:
```yaml
type: aggregate
select:
  - function: count
    alias: user_count
  - function: avg
    field: age
    alias: avg_age
from: users
where:
  - field: created_at
    op: gte
    value: "2025-01-01"
group_by:
  - country
having:
  - field: user_count
    op: gte
    value: 100
```

---

## 5. Acceptance Criteria

- [ ] Aggregate queries return differentially private results
- [ ] Small groups suppressed (< 50 records)
- [ ] Privacy budget tracked per tenant
- [ ] Queries blocked when budget exhausted
- [ ] All queries logged in audit trail
- [ ] Users can see which queries touched their data
- [ ] No individual records ever returned
- [ ] Epsilon configurable per query

---

## 6. Dependencies & Risks

### Dependencies
- PRD-006 (Audit) - Query audit logging
- PRD-010 (ZKP) - Optional ZKP for advanced proofs

### Risks
- **Utility vs Privacy tradeoff:** High privacy = low accuracy
  - *Mitigation:* Configurable epsilon, minimum sample sizes
- **Budget gaming:** Analysts running many low-epsilon queries
  - *Mitigation:* Per-analyst tracking, minimum epsilon per query

---

## Revision History

| Version | Date       | Author      | Changes       |
| ------- | ---------- | ----------- | ------------- |
| 1.0     | 2025-12-17 | Engineering | Initial draft |
