# PRD-017C: Advanced Rate Limiting & Abuse Controls

**Status:** Not Started  
**Priority:** P1 (Security)  
**Owner:** Security Engineering  
**Dependencies:** PRD-017, PRD-017B, PRD-026  
**Last Updated:** 2025-12-24

---

## 1. Purpose

Add advanced abuse controls and adaptive policies beyond the MVP limiter.

## 2. Scope

- Adaptive rate limiting during attacks.
- Per-endpoint custom limits.
- Geolocation-aware limits.
- CAPTCHA challenges on repeated violations.
- Cost-based rate limiting for expensive endpoints.
- Fail-closed mode for high-security deployments.
- Analytics dashboard for rate limit events.
- ML-based anomaly detection hooks.

## 3. Non-Scope

- Distributed store implementation (PRD-017B).
- General admin UI work beyond rate limit dashboards (PRD-026).

## 4. Functional Requirements

1. **Adaptive Policies**
   - Dynamic limits based on attack signals and error rates.

2. **Per-Endpoint Limits**
   - Configure limits by route and client tier.

3. **Challenges**
   - CAPTCHA on repeated violations with cool-downs.

4. **Fail-Closed Mode**
   - Optional hard-deny when limiter store is unavailable.

5. **Analytics**
   - Dashboard: top offenders, hot endpoints, regional distribution.

## 5. Acceptance Criteria

- Adaptive policies can be toggled and audited.
- Per-endpoint limits override class defaults.
- CAPTCHA flows trigger after configured thresholds.
- Fail-closed mode documented and configurable.
- Analytics dashboard surfaces top offenders and trend charts.

## 6. References

- PRD-017: Rate Limiting & Abuse Prevention
- PRD-026: Admin Dashboard & Operations UI

---

## Revision History

| Version | Date       | Author       | Changes       |
| ------- | ---------- | ------------ | ------------- |
| 1.0     | 2025-12-24 | Security Eng | Initial draft |
