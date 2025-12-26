#!/bin/bash
# gh-create-phase1-project.sh
# Creates GitHub Project and Issues for Credo Phase 1: Core Identity Plane
#
# Prerequisites:
#   - gh CLI installed and authenticated (gh auth login)
#   - Repository exists on GitHub
#
# Usage:
#   ./scripts/gh-create-phase1-project.sh

set -euo pipefail

# Configuration
REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")}"
if [[ -z "$REPO" ]]; then
    echo "Error: Could not determine repository. Set GITHUB_REPOSITORY or run from a git repo."
    exit 1
fi

echo "=== Credo Phase 1 Project Setup ==="
echo "Repository: $REPO"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Create Labels
# -----------------------------------------------------------------------------
echo "Creating labels..."

create_label() {
    local name="$1"
    local color="$2"
    local desc="$3"
    if gh label create "$name" --color "$color" --description "$desc" 2>/dev/null; then
        echo "  Created label: $name"
    else
        echo "  Label exists: $name"
    fi
}

# PRD labels
create_label "prd-003" "1d76db" "PRD-003: Registry Integration"
create_label "prd-004" "0e8a16" "PRD-004: Verifiable Credentials"
create_label "prd-005" "d93f0b" "PRD-005: Decision Engine"
create_label "prd-006" "5319e7" "PRD-006: Audit & Compliance"

# Size labels
create_label "size:S" "c2e0c6" "Small: 2-4 hours"
create_label "size:M" "fef2c0" "Medium: 4-8 hours"
create_label "size:L" "f9d0c4" "Large: 8-16 hours"

echo ""

# -----------------------------------------------------------------------------
# Step 2: Create Milestone
# -----------------------------------------------------------------------------
echo "Creating milestone..."

if gh api repos/$REPO/milestones --method POST \
    -f title="Phase 1: Core Identity Plane" \
    -f description="MVP core identity verification capabilities (PRD-003 through PRD-006)" \
    -f state="open" 2>/dev/null; then
    echo "  Created milestone: Phase 1"
else
    echo "  Milestone exists: Phase 1"
fi

MILESTONE_NUMBER=$(gh api repos/$REPO/milestones --jq '.[] | select(.title=="Phase 1: Core Identity Plane") | .number')
echo "  Milestone number: $MILESTONE_NUMBER"
echo ""

# -----------------------------------------------------------------------------
# Step 3: Create Issues
# -----------------------------------------------------------------------------
echo "Creating issues..."

create_issue() {
    local title="$1"
    local body="$2"
    local labels="$3"

    ISSUE_URL=$(gh issue create \
        --title "$title" \
        --body "$body" \
        --label "$labels" \
        --milestone "Phase 1: Core Identity Plane" \
        2>/dev/null || echo "")

    if [[ -n "$ISSUE_URL" ]]; then
        echo "  Created: $title"
        echo "$ISSUE_URL"
    else
        echo "  Failed or exists: $title"
    fi
}

# Issue 1: Citizen Registry Lookup
create_issue "Citizen Registry Lookup" "$(cat <<'EOF'
## Summary
Implement `POST /registry/citizen` endpoint for citizen record lookup from national population registry.

## Acceptance Criteria
- [ ] Endpoint validates national_id format (non-empty, alphanumeric pattern `^[A-Z0-9]{6,20}$`)
- [ ] Requires valid bearer token (401 on invalid)
- [ ] Requires consent for `registry_check` purpose (403 without)
- [ ] Returns full citizen data (name, DOB, address, valid flag) in non-regulated mode
- [ ] Returns minimized data (only valid flag) in regulated mode (`REGULATED_MODE=true`)
- [ ] Emits `registry_citizen_checked` audit event
- [ ] Returns 504 on registry timeout

## Technical Details
- Location: `internal/evidence/registry/`
- Mock client: `MockCitizenClient` with configurable latency
- Data model: `CitizenRecord` struct

## References
- PRD-003 FR-1: Citizen Registry Lookup
- PRD-003 TR-1, TR-2: Data Models, Registry Clients
EOF
)" "prd-003,size:M"

# Issue 2: Sanctions Registry Lookup
create_issue "Sanctions Registry Lookup" "$(cat <<'EOF'
## Summary
Implement `POST /registry/sanctions` endpoint for sanctions/PEP screening.

## Acceptance Criteria
- [ ] Endpoint validates national_id format
- [ ] Requires valid bearer token and consent
- [ ] Returns `listed` boolean and `source` field
- [ ] Does NOT require data minimization (no PII in response)
- [ ] Emits `registry_sanctions_checked` audit event
- [ ] Handles registry timeout gracefully (504)

## Technical Details
- Location: `internal/evidence/registry/`
- Mock client: `MockSanctionsClient` with configurable `listed` flag
- Test data: Hash-based deterministic generation

## References
- PRD-003 FR-2: Sanctions/PEP Lookup
- PRD-003 TR-2: SanctionsRegistryClient Interface
EOF
)" "prd-003,size:M"

# Issue 3: Registry Caching Layer
create_issue "Registry Caching Layer" "$(cat <<'EOF'
## Summary
Implement TTL-based caching for registry lookups to reduce external calls and improve performance.

## Acceptance Criteria
- [ ] Cache citizen records with 5-minute TTL
- [ ] Cache sanctions records with 5-minute TTL
- [ ] Cache hit returns immediately (<5ms p99)
- [ ] Cache miss calls external client and stores result
- [ ] Cache respects TTL (expired entries trigger fresh lookup)
- [ ] `ClearAll()` method for cache invalidation
- [ ] Metrics for cache hit/miss rates

## Technical Details
- Location: `internal/evidence/registry/store_memory.go`
- Interface: `RegistryCacheStore`
- TTL: `config.RegistryCacheTTL = 5 * time.Minute`

## References
- PRD-003 TR-3: Cache Store
- PRD-003 PR-2: Cache Hit Rate (>80% target)
EOF
)" "prd-003,size:S"

# Issue 4: VC Issuance (AgeOver18)
create_issue "VC Issuance (AgeOver18)" "$(cat <<'EOF'
## Summary
Implement `POST /vc/issue` endpoint to issue AgeOver18 verifiable credentials based on citizen registry data.

## Acceptance Criteria
- [ ] Validates credential type is "AgeOver18"
- [ ] Fetches citizen record via registry service
- [ ] Validates citizen.Valid == true (400 if false)
- [ ] Calculates age from DateOfBirth
- [ ] Rejects if age < 18 (400 "User does not meet age requirement")
- [ ] Creates credential with unique ID (`vc_` + uuid)
- [ ] Claims: `is_over_18: true`, `verified_via: national_registry`
- [ ] Minimizes claims in regulated mode (removes `verified_via`)
- [ ] Stores credential in VCStore
- [ ] Emits `vc_issued` audit event

## Technical Details
- Location: `internal/evidence/vc/`
- Service: `VCService.Issue()`
- Age calculation: Handle birthday not yet passed this year

## References
- PRD-004 FR-1: Issue Verifiable Credential
- PRD-004 TR-1, TR-2: Data Models, Service Layer
EOF
)" "prd-004,size:M"

# Issue 5: VC Verification
create_issue "VC Verification" "$(cat <<'EOF'
## Summary
Implement `POST /vc/verify` endpoint to verify previously issued credentials.

## Acceptance Criteria
- [ ] Validates credential_id is provided (400 if missing)
- [ ] Retrieves credential from VCStore
- [ ] Returns 404 if credential not found
- [ ] Returns `valid: true` with credential details if found
- [ ] Includes claims in response
- [ ] Emits `vc_verified` audit event
- [ ] Future: Check revocation status

## Technical Details
- Location: `internal/evidence/vc/`
- Service: `VCService.Verify()`
- Response: `VerifyResult` struct

## References
- PRD-004 FR-2: Verify Credential
EOF
)" "prd-004,size:S"

# Issue 6: Decision Evaluate Endpoint
create_issue "Decision Evaluate Endpoint" "$(cat <<'EOF'
## Summary
Implement `POST /decision/evaluate` endpoint that orchestrates evidence gathering and returns authorization decisions.

## Acceptance Criteria
- [ ] Parses purpose and context from request
- [ ] Gathers evidence in parallel (errgroup with shared context):
  - Citizen record (registry)
  - Sanctions record (registry)
  - Existing AgeOver18 VC (store lookup)
- [ ] Early cancellation on first failure/timeout
- [ ] Emits per-source latency/cache metrics
- [ ] Derives identity attributes (IsOver18 from DOB)
- [ ] Builds DecisionInput with no PII (DerivedIdentity only)
- [ ] Calls decision service for rule evaluation
- [ ] Emits `decision_made` audit event
- [ ] Returns structured outcome (status, reason, conditions, evidence)

## Technical Details
- Location: `internal/decision/`
- Handler: `handleDecisionEvaluate`
- Service: `decisionService.Evaluate()`
- Concurrency: `errgroup` for parallel evidence gathering

## References
- PRD-005 FR-1: Evaluate Decision
- PRD-005 TR-2: Service Layer (orchestration requirements)
EOF
)" "prd-005,size:L"

# Issue 7: Decision Rules (age_verification)
create_issue "Decision Rules (age_verification)" "$(cat <<'EOF'
## Summary
Implement business rule logic for `age_verification` purpose in the decision service.

## Acceptance Criteria
- [ ] Rule chain evaluation order:
  1. IF sanctions.Listed == true → FAIL (reason: "sanctioned")
  2. IF citizen.Valid == false → FAIL (reason: "invalid_citizen")
  3. IF derived.IsOver18 == false → FAIL (reason: "underage")
  4. IF hasCredential == true → PASS (reason: "all_checks_passed")
  5. ELSE → PASS_WITH_CONDITIONS (reason: "missing_credential", conditions: ["obtain_age_credential"])
- [ ] Support `sanctions_screening` purpose (sanctions check only)
- [ ] DecisionOutcome includes status, reason, conditions
- [ ] No PII in decision output (only derived flags)

## Technical Details
- Location: `internal/decision/service.go`
- Models: `DecisionInput`, `DecisionOutcome`, `DerivedIdentity`
- Function: `deriveIsOver18()` with proper date math

## References
- PRD-005 Section 4: Decision Rules by Purpose
- PRD-005 TR-1, TR-3: Data Models, Identity Derivation
EOF
)" "prd-005,size:M"

# Issue 8: Async Audit Publisher
create_issue "Async Audit Publisher" "$(cat <<'EOF'
## Summary
Implement non-blocking audit event publisher with buffered channel and background worker.

## Acceptance Criteria
- [ ] Publisher owns bounded channel (configurable size)
- [ ] `Emit()` is non-blocking with backpressure policy
- [ ] Background worker persists events to store
- [ ] Worker runs with context.Context
- [ ] Graceful shutdown drains queue before exit
- [ ] Metrics for queue depth and dropped events
- [ ] Span/metric annotations for latency and failures

## Technical Details
- Location: `internal/audit/publisher.go`
- Interface: `Publisher.Emit(ctx, event)`
- Channel: Bounded, configurable buffer size
- Shutdown: Drain on context cancel

## References
- PRD-006 FR-1: Emit Audit Events
- PRD-006 TR-2: Publisher (Non-Blocking)
EOF
)" "prd-006,size:M"

# Issue 9: User Data Export (GDPR)
create_issue "User Data Export (GDPR)" "$(cat <<'EOF'
## Summary
Implement `GET /me/data-export` endpoint for GDPR Article 15 (Right to Access).

## Acceptance Criteria
- [ ] Requires valid bearer token (401 on invalid)
- [ ] Extracts user ID from token
- [ ] Returns all audit events for the user
- [ ] Supports optional filters:
  - `from` - Start date (ISO 8601)
  - `to` - End date (ISO 8601)
  - `action` - Filter by action type
- [ ] Response includes: user_id, export_date, events array, total count
- [ ] Each event: id, timestamp, action, purpose, decision, reason
- [ ] Emits `data_exported` audit event

## Technical Details
- Location: `internal/transport/http/handlers_me.go`
- Store: `auditStore.ListByUser(userID)`
- Filtering: Apply date range and action filters

## References
- PRD-006 FR-2: Export User Audit Log
- GDPR Article 15: Right of access
EOF
)" "prd-006,size:M"

# Issue 10: Audit Search (Compliance)
create_issue "Audit Search (Compliance)" "$(cat <<'EOF'
## Summary
Implement `GET /audit/search` endpoint for compliance investigations with cross-user search capability.

## Acceptance Criteria
- [ ] Requires admin/compliance role (403 without)
- [ ] Supports filters:
  - `user_id` (optional)
  - `action` (optional, multi-value)
  - `purpose` (optional)
  - `from`, `to` (ISO timestamps)
  - `decision` (optional)
- [ ] Backed by Elasticsearch/OpenSearch index
- [ ] Returns results with: id, timestamp, user_id, action, purpose, decision, reason
- [ ] Includes `total` count and `took_ms` timing
- [ ] Falls back to raw event export on index errors

## Technical Details
- Location: `internal/audit/` + `internal/transport/http/`
- Indexing: Events streamed to ES/OpenSearch
- Daily indices for retention management
- Eventually consistent (≤1s lag acceptable)

## Future Considerations
- Kafka/NATS transport for event streaming
- Dead-letter handling for indexing errors
- Redis cache for hot queries (recent 24h)

## References
- PRD-006 FR-3: Searchable Audit Queries
- PRD-006 TR-5: Event Streaming & Indexing Pipeline
EOF
)" "prd-006,size:L"

echo ""

# -----------------------------------------------------------------------------
# Step 4: Create Project
# -----------------------------------------------------------------------------
echo "Creating GitHub Project..."

PROJECT_TITLE="Phase 1: Core Identity Plane"

# Create project using gh project create
PROJECT_URL=$(gh project create --owner "@me" --title "$PROJECT_TITLE" 2>/dev/null || echo "")

if [[ -n "$PROJECT_URL" ]]; then
    echo "  Created project: $PROJECT_TITLE"
    echo "  URL: $PROJECT_URL"
else
    echo "  Project may already exist or creation failed"
    echo "  You can create it manually: gh project create --title \"$PROJECT_TITLE\""
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. View issues: gh issue list --milestone 'Phase 1: Core Identity Plane'"
echo "2. View project: gh project list"
echo "3. Add issues to project board manually or via: gh project item-add"
echo ""
echo "To add all Phase 1 issues to a project:"
echo "  PROJECT_NUM=\$(gh project list --format json | jq '.projects[] | select(.title==\"Phase 1: Core Identity Plane\") | .number')"
echo "  gh issue list --milestone 'Phase 1: Core Identity Plane' --json number -q '.[].number' | xargs -I {} gh project item-add \$PROJECT_NUM --owner @me --url https://github.com/$REPO/issues/{}"
