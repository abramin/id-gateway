# PRD-023: Fraud Detection & Security Intelligence

**Status:** Not Started
**Priority:** P1 (High)
**Owner:** Engineering Team
**Dependencies:** PRD-001, PRD-005, PRD-007B, PRD-013
**Last Updated:** 2025-12-12

## 1. Overview

### Problem Statement
System vulnerable to account takeover, identity fraud, and credential stuffing without unified fraud detection.

### Goals
- Login anomaly detection (impossible travel, unusual device)
- Velocity checks (too many actions too fast)
- Credential stuffing detection
- Bot detection (CAPTCHA integration)
- Device reputation scoring
- Behavioral biometrics (typing patterns)
- Integration with threat intelligence feeds
- Security event correlation

## 2. Functional Requirements

### FR-1: Anomaly Detection
**Impossible Travel:** Login from New York, then London 1 hour later → flag
**New Device:** Login from never-seen device → require MFA

### FR-2: Velocity Checks
**Limit:** Max 5 consent grants per minute
**Limit:** Max 10 registry lookups per hour

### FR-3: Device Fingerprinting
**Collect:** User-agent, screen resolution, timezone, canvas fingerprint
**Score:** New device = higher risk score

### FR-4: Threat Intel Integration
**Check:** Email/IP against breach databases (HaveIBeenPwned API)
**Check:** IP reputation against threat feeds

## 3. Acceptance Criteria
- [ ] Impossible travel detected and alerted
- [ ] Velocity limits enforced
- [ ] Device fingerprints collected
- [ ] Threat intel checked on login
- [ ] High-risk logins require step-up auth

## Revision History
| Version | Date       | Author       | Changes     |
| ------- | ---------- | ------------ | ----------- |
| 1.0     | 2025-12-12 | Product Team | Initial PRD |
