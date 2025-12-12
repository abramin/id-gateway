# PRD-022: Account Recovery & Credential Management

**Status:** Not Started
**Priority:** P1 (High)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-018 (Notifications)
**Last Updated:** 2025-12-12

## 1. Overview

### Problem Statement
Users cannot recover locked/lost accounts, leading to poor retention and support overhead.

### Goals
- Password reset flow (email-based)
- Account unlock (after brute force lockout)
- Email verification & change flow
- Security questions as recovery option
- Credential strength requirements
- Password history (prevent reuse)

## 2. Functional Requirements

### FR-1: Password Reset
**Endpoint:** `POST /auth/password/reset-request`
**Input:** `{"email": "user@example.com"}`
**Output:** `{"sent": true, "message": "Check your email"}`

### FR-2: Account Unlock
**Automatic unlock after 30 minutes of last failed attempt**

### FR-3: Email Verification
**Send verification link on registration**
**Resend via:** `POST /auth/email/resend-verification`

## 3. Acceptance Criteria
- [ ] Password reset emails delivered
- [ ] Reset links expire after 24 hours
- [ ] Account auto-unlocks after cooldown
- [ ] Email verification required before sensitive ops

## Revision History
| Version | Date       | Author       | Changes     |
| ------- | ---------- | ------------ | ----------- |
| 1.0     | 2025-12-12 | Product Team | Initial PRD |
