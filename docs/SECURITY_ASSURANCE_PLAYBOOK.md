# Security Assurance Playbook

This playbook defines how Credo teams plan, execute, and evidence security assurance across the SDLC. It focuses on pre-production controls with clear scope, owners, and measurable SLAs.

## Scope and Objectives
- **Objectives:** Prevent avoidable vulnerabilities before release, detect regressions early, and provide auditable evidence for compliance and customer due diligence.
- **In scope:** Application/backend services, APIs/handlers, service-layer business logic, infrastructure-as-code, container images, CI/CD pipelines, third-party libraries and containers, API contracts, and feature flag behaviors.
- **Out of scope:** Production red-teaming (optional/on-demand), customer-managed environments, and exploratory research spikes without user data. These can be added under a separate statement of work.

## Threat Modeling
- **Methodology:** STRIDE for component-level analysis; PASTA for end-to-end user journey or data-flow reviews where multi-service abuse paths exist.
- **Artifacts:** Data-flow diagrams, trust boundary map, prioritized threat list with mitigations, abuse/misuse cases, and residual-risk register linked to Jira tickets.
- **When required:**
  - New feature epics, major architecture changes (new service, new data store, external integration), auth/crypto changes, and any change handling PII/credentials/secrets.
  - Revisit prior models when changing dependencies that alter trust boundaries (e.g., IdP, gateway, ingress).
  - Lightweight checklist applied to minor changes; full PASTA/STRIDE package for major releases.

## Automated Security Testing
- **SAST:** Semgrep CI job on all branches; blocking severity ≥ High with rule set `p/owasp-top-ten` plus custom Credo rules. Coverage SLA: ≥90% of backend services have Semgrep coverage in CI pipelines.
- **DAST:** ZAP/Burp automation against ephemeral preview envs for PRs touching handlers/routes; block releases on High/Critical findings. Include authenticated and unauthenticated scans; baseline + active scans weekly on `main`.
- **IAST/Runtime hardening:** Optional IAST agent in staging during hardening sprints; required for services that process secrets or credentials.
- **Fuzzing:** Fuzz JSON schema validators, token/credential parsers, and protobuf/grpc decoders. Run nightly; block release if crashes or panic signatures appear.
- **CI gates:** Security jobs must pass before merge to `main` and before release tags. Flaky findings require issue+owner+due date to proceed.
- **Triage SLAs:** Critical: 24h, High: 3 business days, Medium: 10 business days, Low: best effort. Violations are reported in weekly risk review.

## Dependency and Container Scanning
- **SBOM:** Generate SBOM (CycloneDX) for backend Go modules, frontend packages, and container images during CI. Publish as build artifact.
- **Vulnerability thresholds:** Block on Critical/High CVEs with available fixes or known exploits. Medium allowed only with documented mitigation and timebound plan. Low informational allowed.
- **Exemptions:** Require security approval + Jira record referencing CVE, impact statement, mitigation, and expiry date. Auto-revalidate exemptions every 90 days.
- **Container scanning:** Use Trivy on images before pushing to registries; block on Critical/High and outdated base images.

## Pen-Test Harnesses and Synthetic Attack Traffic
- **Environments:** Dedicated staging with production-parity configs and seeded synthetic identities. No production data.
- **Data seeding:** Use deterministic fixtures (test issuers, wallets, credentials, API clients) to support repeatable attack paths. Refresh before each pen-test cycle.
- **Harness:** Provide scripted flows for auth bypass attempts, token replay, JWT tampering, consent abuse, and rate-limit evasion. Integrate into e2e test harness for regression checks.
- **Success criteria:** Demonstrate exploit blocked or alert generated; produce reproducible steps, logs, and patch plan. Pen-test exit requires zero open Critical/High issues.

## Workflow and Governance
- **Security review points:**
  - **Design:** Threat model required; attach diagrams and risk register to the design doc/PRD.
  - **Implementation:** SAST/DAST/fuzzing/Trivy jobs must pass; dependency diff reviewed; security checklist completed in PR description.
  - **Pre-release:** Pen-test results, SBOM, and vulnerability report attached to release ticket. Change management sign-off.
- **Approvers:** At least one security engineer and one service owner for high-risk changes; security sign-off required for exemptions and crypto/auth changes.
- **Evidence to attach to PRs:** Links to threat model, Semgrep/ZAP/Trivy logs, SBOM artifact, exemption records, and checklist outcomes.

## Tooling Integrations
- **ZAP/Burp:** Automated nightly and per-PR scans via GitHub Actions/Make; include authenticated session scripts and anti-CSRF handling.
- **Semgrep:** Central rule packs with repo-specific allowlists; failures block merge. Auto-open issues for suppressed findings with expiry.
- **Trivy:** Scan Go modules, NPM packages, and container images; enforce base-image freshness.
- **OPA policies:** Apply to Kubernetes manifests, Terraform, and CI configs to enforce guardrails (no public S3 buckets, TLS required, prohibited ports/secrets-in-plain-text). Failing policies block merge.

## Metrics and Reporting
- **Defect density:** Security findings per KLOC and per service; target downward trend month-over-month.
- **MTTR:** Critical/High MTTR tracked against SLA; report variance weekly.
- **Coverage:** Percentage of services with SAST/DAST/fuzzing/Trivy + threat models; goal ≥90% coverage per category.
- **Drift detection:** Weekly comparison of IaC state vs. policy baseline; alert on security group/ingress drift and unpinned dependencies.
- **Transparency:** Monthly security report summarizing new findings, SLA adherence, exemptions, and coverage gaps.
