# PRD-026: Admin Dashboard & Operations UI

**Status:** Not Started
**Priority:** P2 (Medium)
**Owner:** Engineering Team
**Dependencies:** PRD-001-007, PRD-020
**Last Updated:** 2025-12-12

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

## Revision History
| Version | Date       | Author       | Changes     |
| ------- | ---------- | ------------ | ----------- |
| 1.0     | 2025-12-12 | Product Team | Initial PRD |
