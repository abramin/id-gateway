# PRD-012: Cloud Connectors for Credo Audit & Identity Event Export

**Status:** Draft  
**Priority:** P1 (Production Hardening)  
**Owner:** Identity Engineering  
**Last Updated:** 2025-12-09

---

## 1. Overview

### Problem Statement

Credo generates high-value identity data: authentication logs, consent events, policy decisions, and administrative actions. Customers frequently need to ship these logs into their own **Elastic** clusters for SIEM, observability, compliance reporting, and incident response.

Today, customers must manually configure cloud roles, network paths, and secret handling for AWS, Azure, and GCP. This creates security risk, operational friction, and inconsistent implementations. Credo needs **first-class Cloud Connectors** that securely integrate with Elastic workloads running in these clouds, enforcing least privilege, proper secret management, and full lifecycle auditability.

### Goal

Provide a secure, standardized way for Credo tenants to connect their identity audit streams to customer-owned Elastic deployments in AWS, Azure, and Google Cloud.

The connectors must:

- Use provider-native IAM identities with least privilege.
- Handle secrets exclusively via vault-backed references.
- Support threat modeling and secure review before activation.
- Emit metrics and audit logs for all connector actions.
- Integrate naturally with Credo's consent, audit, and compliance layers.

### Non-Goals

- Running Elastic directly inside Credo.
- Managing customer cloud billing or onboarding.
- Replacing the audit event system; connectors only deliver events.

---

## 2. User Stories

- **As a platform engineer**, I want to connect my Credo tenant to my Elastic cluster in AWS/Azure/GCP without writing custom IAM policies or scripts.
- **As a security engineer**, I want connectors that enforce least privilege and use vault-backed secret references so I can approve integrations quickly.
- **As a compliance officer**, I want exported audit data tagged with consent purpose and retention metadata to support investigations and regulatory obligations.
- **As an SRE**, I want metrics and health checks for each connector so I can detect failures and scale the workload.

---

## 3. Functional Requirements

### FR-1: Connector Catalog

- Provide CRUD APIs to manage connectors for `aws`, `azure`, and `gcp`.
- A connector includes:

  - Provider type
  - Region
  - Target Elastic endpoint or PrivateLink/PSC identifier
  - Capabilities: `["audit-export"]` (future: `risk-signals`)
  - Secret references (vault URIs only)
  - Provider identity reference (IAM role, Managed Identity, Service Account)
  - Consent purpose mappings
  - Retention policy

- Connector lifecycle: `draft` → `validated` → `active` → `suspended` → `retired`.

### FR-2: Secret Management

- Secrets must be stored only as vault URIs (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).
- Literal secrets are rejected at API level.
- `POST /connectors/{id}/secrets/rotate` triggers automatic provider-specific secret rotation.

### FR-3: Least Privilege Access Templates

Provide provider-specific role templates for publishing to customer Elastic deployments:

- **AWS**: IAM role restricted to:

  - `es:ESHttpPost` and `es:ESHttpPut` on a specific index or endpoint.
  - KMS decryption for a single key.
  - Optional VPC endpoint policy scoping.

- **Azure**: Managed Identity with:

  - Role assignment to target Elastic resource.
  - Key Vault read permission for specific secret paths.

- **GCP**: Service Account with:
  - IAM permission for Elastic PSC endpoint.
  - Secret Manager access to specific secret paths.

During activation, Credo validates the identity policy using dry-run policy simulation (where supported).

### FR-4: Data Export Pipeline

- Export audit and identity event streams (auth logs, consent events, policy decisions, admin actions) over TLS with optional mTLS.
- Support batching and retry logic.
- Emit connector-level metrics:
  - request rate
  - batch latency
  - failures and throttling events
  - secret rotation age

### FR-5: Consent & Compliance Integration

- Connector activation requires mapping audit data categories to consent purposes (references PRD-002).
- Enforce retention days (auto-delete or anonymize exported data).
- Generate an “activation evidence bundle”:
  - threat model record
  - secure code review checklist
  - IAM/identity diff summary

---

## 4. Security Requirements

- **Least Privilege:** No wildcard permissions in any cloud template.
- **Secret Management:** Only vault references are persisted; no inline secrets in config or env vars.
- **Threat Modeling:** Every provider or capability addition requires an updated STRIDE model before connector status can move to `validated`.
- **Secure Code Reviews:** Require secure pipeline checks (lint, SAST, dependency checks) before merging connector code.
- **Network Hardening:** TLS 1.2+, optional mTLS, and optional private networking (VPC Endpoint, Private Link, Private Service Connect).

---

## 5. Non-Functional Requirements

- **Availability:** Control-plane APIs ≥99.9% monthly.
- **Performance:** Export latency p95 <150ms intra-region under normal load.
- **Scalability:** Support at least 50 connectors per provider with isolated identities.
- **Auditability:** All actions recorded immutably and exportable to Elastic.

---

## 6. API Contracts (Draft)

### Create Connector

`POST /connectors`

```json
{
  "provider": "aws",
  "region": "eu-west-1",
  "elastic_endpoint": "https://my-es.ap-southeast-1.aws.com",
  "capabilities": ["audit-export"],
  "secret_refs": ["vault://kv/aws/credo-audit-signer"],
  "identity_ref": "arn:aws:iam::123456789012:role/credo-audit-exporter",
  "consent_purposes": ["security_audit", "compliance_reporting"],
  "retention_days": 30,
  "network": { "vpc_endpoint": "vpce-abc123" }
}
```
