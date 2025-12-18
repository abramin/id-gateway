# PRD-006B: Cryptographic Audit (Merkle Tree)

**Status:** Not Started
**Priority:** P1 (High - Showcase Feature)
**Owner:** Engineering Team
**Dependencies:** PRD-006 complete
**Last Updated:** 2025-12-06

---

## 1. Overview

### Problem Statement

The current audit system (PRD-006) provides append-only logging, but cannot cryptographically prove that logs haven't been tampered with. For regulated systems and compliance scenarios, we need verifiable proof that audit events are authentic and unmodified.

### Goals

- Replace simple append-only audit with cryptographically verifiable Merkle tree structure
- Provide tamper-evident proof for each audit event
- Enable verification of audit log integrity without trusted third party
- Generate inclusion proofs that any event exists in the audit trail
- Detect tampering attempts through cryptographic verification
- Maintain backward compatibility with existing audit event structure

### Non-Goals

- Distributed consensus (blockchain)
- External timestamp authority integration
- Public blockchain anchoring
- Real-time verification during event emission
- Audit log encryption (separate concern)
- Multi-party audit verification

---

## 2. User Stories

**As a** compliance officer
**I want to** cryptographically verify audit logs haven't been tampered with
**So that** I can prove regulatory compliance with high confidence

**As a** security auditor
**I want to** receive a proof that a specific event exists in the audit trail
**So that** I can verify claims without accessing the entire log

**As a** system administrator
**I want to** detect if anyone has tampered with audit logs
**So that** I can identify security breaches

**As a** developer
**I want to** understand cryptographic guarantees of the audit system
**So that** I can document and communicate it clearly

---

## 3. Functional Requirements

### FR-1: Merkle Tree Construction

**Internal Process** (no direct endpoint)

**Description:** As audit events are appended, build a Merkle tree where each leaf is a hash of an event, and each parent node is a hash of its children.

**Merkle Tree Structure:**

```
                Root Hash
               /          \
         Hash(A,B)      Hash(C,D)
         /      \        /      \
    Hash(A) Hash(B) Hash(C) Hash(D)
      |       |       |       |
   Event1  Event2  Event3  Event4
```

**Tree Properties:**

- Each event is a leaf node
- Leaf hash = SHA256(eventID + timestamp + userID + action + ...)
- Parent hash = SHA256(leftChild + rightChild)
- Root hash = cryptographic fingerprint of entire audit log
- Changing any event changes root hash (tamper-evident)

**Implementation Notes:**

- Tree is append-only (no updates or deletes)
- Tree is incrementally updated as events arrive
- Root hash is stored separately as "tree state"
- Each event stores its position in tree (for proof generation)

---

### FR-2: Generate Inclusion Proof

**Endpoint:** `GET /audit/proof/{event_id}`

**Description:** Generate a Merkle proof that a specific event exists in the audit trail.

**Input:**

- Path param: `event_id` (e.g., "evt_abc123")
- Header: `Authorization: Bearer <admin_token>` (optional: restrict to admins)

**Output (Success - 200):**

```json
{
  "event_id": "evt_abc123",
  "event_hash": "a1b2c3...",
  "tree_root": "xyz789...",
  "proof": [
    { "position": "right", "hash": "d4e5f6..." },
    { "position": "left", "hash": "g7h8i9..." },
    { "position": "right", "hash": "j0k1l2..." }
  ],
  "tree_size": 1247,
  "generated_at": "2025-12-06T10:00:00Z"
}
```

**Business Logic:**

1. Retrieve event from AuditStore
2. If not found, return 404
3. Get event's position in Merkle tree
4. Collect sibling hashes along path to root
5. Return proof array with position indicators
6. Include current root hash for verification

**Merkle Proof Verification (Client-Side):**

```
1. Hash event data → leafHash
2. For each proof element:
   - If position == "right": hash = SHA256(leafHash + proof.hash)
   - If position == "left": hash = SHA256(proof.hash + leafHash)
   - leafHash = hash
3. Final hash should equal tree_root
```

**Error Cases:**

- 404 Not Found: Event doesn't exist
- 401 Unauthorized: Invalid admin token (if restricted)
- 500 Internal Server Error: Tree corruption detected

---

### FR-3: Verify Inclusion Proof

**Endpoint:** `POST /audit/verify-proof`

**Description:** Verify that a given proof demonstrates an event exists in the audit trail with the claimed root hash.

**Input:**

```json
{
  "event_id": "evt_abc123",
  "event_data": {
    "timestamp": "2025-12-06T09:00:00Z",
    "user_id": "user_123",
    "action": "consent_granted",
    "purpose": "registry_check"
  },
  "proof": [
    { "position": "right", "hash": "d4e5f6..." },
    { "position": "left", "hash": "g7h8i9..." }
  ],
  "claimed_root": "xyz789..."
}
```

**Output (Success - 200, Valid):**

```json
{
  "valid": true,
  "verified_root": "xyz789...",
  "message": "Proof is valid. Event exists in audit trail."
}
```

**Output (Success - 200, Invalid):**

```json
{
  "valid": false,
  "expected_root": "xyz789...",
  "computed_root": "abc123...",
  "message": "Proof verification failed. Event may be tampered or proof incorrect."
}
```

**Business Logic:**

1. Hash event_data to get leaf hash
2. Apply proof steps sequentially
3. Compare final hash with claimed_root
4. Return validation result

**Error Cases:**

- 400 Bad Request: Malformed proof or missing fields
- 500 Internal Server Error: Verification logic failure

---

### FR-4: Get Current Root Hash

**Endpoint:** `GET /audit/tree-root`

**Description:** Return the current Merkle tree root hash (state of entire audit log).

**Input:** None (or optional admin auth)

**Output (Success - 200):**

```json
{
  "root_hash": "xyz789abc...",
  "tree_size": 1247,
  "last_updated": "2025-12-06T10:00:00Z"
}
```

**Business Logic:**

1. Retrieve current tree root from MerkleTreeStore
2. Return root hash, tree size, and timestamp

**Use Case:** Clients can periodically snapshot root hash to detect tampering.

---

### FR-5: Detect Tampering

**Internal Function** (no endpoint, automatic)

**Description:** On every tree access, verify integrity by recomputing root hash from leaves and comparing with stored root.

**Tampering Detection:**

- If stored root ≠ computed root → Log CRITICAL alert
- If event count mismatches tree size → Log alert
- If any leaf hash doesn't match event data → Log alert

**Response to Tampering:**

- Do NOT auto-repair (preserve evidence)
- Log incident to separate tamper log
- Return error to client
- Notify administrators (future: send alert)

---

## 4. Technical Requirements

### TR-1: Data Models

**Location:** `internal/audit/merkle.go` (new file)

```go
type MerkleTree struct {
    Root      *MerkleNode
    Leaves    []*MerkleNode
    Size      int
    RootHash  string
    UpdatedAt time.Time
}

type MerkleNode struct {
    Hash     string
    Left     *MerkleNode
    Right    *MerkleNode
    IsLeaf   bool
    EventID  string // Only for leaf nodes
    Position int    // Position in tree (for proof generation)
}

type InclusionProof struct {
    EventID   string
    EventHash string
    TreeRoot  string
    TreeSize  int
    Proof     []ProofElement
}

type ProofElement struct {
    Position string // "left" or "right"
    Hash     string
}

type VerifyRequest struct {
    EventID     string
    EventData   Event
    Proof       []ProofElement
    ClaimedRoot string
}

type VerifyResult struct {
    Valid        bool
    ComputedRoot string
    Message      string
}
```

### TR-2: Merkle Tree Builder

**Location:** `internal/audit/merkle_builder.go` (new file)

```go
type MerkleBuilder struct {
    tree *MerkleTree
    mu   sync.RWMutex
}

func (b *MerkleBuilder) AppendEvent(ev Event) (string, error) {
    b.mu.Lock()
    defer b.mu.Unlock()

    // 1. Hash event to create leaf
    leafHash := hashEvent(ev)
    leaf := &MerkleNode{
        Hash:     leafHash,
        IsLeaf:   true,
        EventID:  ev.ID,
        Position: len(b.tree.Leaves),
    }

    // 2. Append leaf to tree
    b.tree.Leaves = append(b.tree.Leaves, leaf)

    // 3. Rebuild tree from leaves (simple approach for MVP)
    b.rebuildTree()

    return leafHash, nil
}

func (b *MerkleBuilder) rebuildTree() {
    // Build tree bottom-up from leaves
    // This is O(n) but acceptable for MVP
    // Production: incremental update O(log n)
}

func hashEvent(ev Event) string {
    data := fmt.Sprintf("%s|%s|%s|%s|%s",
        ev.ID,
        ev.Timestamp.Format(time.RFC3339),
        ev.UserID,
        ev.Action,
        ev.Purpose,
    )
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
```

### TR-3: Proof Generator

**Location:** `internal/audit/proof_generator.go` (new file)

```go
type ProofGenerator struct {
    tree *MerkleTree
}

func (g *ProofGenerator) GenerateProof(eventID string) (*InclusionProof, error) {
    // 1. Find leaf with eventID
    leaf := g.findLeaf(eventID)
    if leaf == nil {
        return nil, errors.New("event not found")
    }

    // 2. Collect sibling hashes along path to root
    proof := []ProofElement{}
    current := leaf

    for current != g.tree.Root {
        sibling := g.getSibling(current)
        if sibling != nil {
            position := "left"
            if g.isRightChild(current) {
                position = "right"
            }
            proof = append(proof, ProofElement{
                Position: position,
                Hash:     sibling.Hash,
            })
        }
        current = g.getParent(current)
    }

    return &InclusionProof{
        EventID:   eventID,
        EventHash: leaf.Hash,
        TreeRoot:  g.tree.RootHash,
        TreeSize:  g.tree.Size,
        Proof:     proof,
    }, nil
}
```

### TR-4: Proof Verifier

**Location:** `internal/audit/proof_verifier.go` (new file)

```go
type ProofVerifier struct{}

func (v *ProofVerifier) Verify(req VerifyRequest) VerifyResult {
    // 1. Hash event data
    leafHash := hashEvent(req.EventData)

    // 2. Apply proof steps
    computedHash := leafHash
    for _, elem := range req.Proof {
        if elem.Position == "right" {
            computedHash = hashPair(computedHash, elem.Hash)
        } else {
            computedHash = hashPair(elem.Hash, computedHash)
        }
    }

    // 3. Compare with claimed root
    valid := computedHash == req.ClaimedRoot

    return VerifyResult{
        Valid:        valid,
        ComputedRoot: computedHash,
        Message:      formatMessage(valid),
    }
}

func hashPair(left, right string) string {
    combined := left + right
    hash := sha256.Sum256([]byte(combined))
    return hex.EncodeToString(hash[:])
}
```

### TR-5: Store Updates

**Update:** `internal/audit/store.go`

```go
type Store interface {
    Append(ctx context.Context, ev Event) error
    ListByUser(ctx context.Context, userID string) ([]Event, error)

    // NEW: Merkle tree methods
    AppendWithProof(ctx context.Context, ev Event) (leafHash string, err error)
    GetTreeRoot(ctx context.Context) (string, int, error) // root, size
    GetProof(ctx context.Context, eventID string) (*InclusionProof, error)
}
```

### TR-6: HTTP Handlers

**Location:** `internal/transport/http/handlers_audit.go` (new file)

```go
func (h *Handler) handleGetProof(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleVerifyProof(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleGetTreeRoot(w http.ResponseWriter, r *http.Request)
```

---

## 5. Implementation Steps

### Phase 1: Merkle Tree Core (3-4 hours)

1. Create `internal/audit/merkle.go` with data models
2. Implement `MerkleBuilder` with tree construction logic
3. Unit tests for tree building with 1, 2, 4, 8 events

### Phase 2: Proof Generation (2-3 hours)

1. Implement `ProofGenerator.GenerateProof()`
2. Test proof generation for various tree positions
3. Test edge cases (single event, full balanced tree)

### Phase 3: Proof Verification (2 hours)

1. Implement `ProofVerifier.Verify()`
2. Test valid and invalid proofs
3. Test tampered event detection

### Phase 4: Store Integration (2-3 hours)

1. Update `InMemoryAuditStore` to use MerkleBuilder
2. Implement `AppendWithProof()` method
3. Store tree state alongside events

### Phase 5: HTTP Handlers (2 hours)

1. Implement handleGetProof
2. Implement handleVerifyProof
3. Implement handleGetTreeRoot

### Phase 6: Testing & Documentation (2-3 hours)

1. Integration tests for full flow
2. Manual testing with curl
3. Write documentation explaining cryptographic guarantees
4. Create diagrams of Merkle tree structure

---

## 6. Acceptance Criteria

- [ ] Audit events build a Merkle tree as they're appended
- [ ] Root hash changes when new events are added
- [ ] Root hash is reproducible from event data
- [ ] Inclusion proofs can be generated for any event
- [ ] Valid proofs verify successfully
- [ ] Invalid/tampered proofs fail verification
- [ ] Tampering with event data changes leaf hash and invalidates proof
- [ ] Root hash can be queried at any time
- [ ] System detects if stored root doesn't match computed root
- [ ] Performance acceptable for 10K+ events
- [ ] Documentation explains cryptographic properties clearly

---

## 7. Testing

### Unit Tests

```go
// Test tree construction
func TestMerkleTreeConstruction(t *testing.T) {
    // Build tree with 4 events
    // Verify root hash
    // Add 5th event
    // Verify root hash changed
}

// Test proof generation
func TestProofGeneration(t *testing.T) {
    // Generate proof for each event
    // Verify proof verifies correctly
}

// Test tamper detection
func TestTamperDetection(t *testing.T) {
    // Generate proof
    // Modify event data
    // Verify proof fails
}
```

### Integration Tests

```bash
# Emit several audit events
curl -X POST /auth/authorize ...
curl -X POST /auth/consent ...

# Get tree root
curl http://localhost:8080/audit/tree-root
# Expected: {"root_hash": "...", "tree_size": 2}

# Generate proof for event
curl http://localhost:8080/audit/proof/evt_abc123
# Expected: {"proof": [...], "tree_root": "..."}

# Verify proof
curl -X POST http://localhost:8080/audit/verify-proof \
  -d '{
    "event_id": "evt_abc123",
    "event_data": {...},
    "proof": [...],
    "claimed_root": "..."
  }'
# Expected: {"valid": true}

# Test tampered proof (modify event_data)
curl -X POST http://localhost:8080/audit/verify-proof \
  -d '{"event_data": {"action": "TAMPERED"}, ...}'
# Expected: {"valid": false}
```

---

## 8. Performance Considerations

### Time Complexity

- **Append event:** O(n) for MVP (rebuild tree), O(log n) with incremental update
- **Generate proof:** O(log n) (walk tree to root)
- **Verify proof:** O(log n) (apply proof steps)
- **Get root:** O(1) (cached)

### Space Complexity

- **Tree storage:** O(n) nodes for n events
- **Proof size:** O(log n) hashes

### Optimization Strategies (Future)

1. **Incremental tree update:** Only rebuild affected branch
2. **Proof caching:** Cache proofs for recently accessed events
3. **Tree snapshots:** Periodically save tree state to disk
4. **Pruning:** Archive old subtrees (keep root hashes)

---

## 9. Security Properties

### Cryptographic Guarantees

**Tamper Evidence:**

- Modifying any event changes its leaf hash
- Changed leaf hash propagates up to root
- Root hash acts as cryptographic fingerprint
- Any tampering is detectable by verifying root

**Inclusion Proof:**

- Proof demonstrates event exists in specific position
- Cannot forge proof without knowing all sibling hashes
- Proof size is logarithmic (compact)

**Non-Repudiation:**

- Once event is in tree, cannot deny it existed
- Root hash serves as commitment to all events

**Limitations (Not Provided):**

- **Timestamp proof:** No guarantee event occurred at claimed time (need external timestamp authority)
- **Deletion resistance:** Relies on system not allowing deletes (append-only storage)
- **Distributed verification:** Single system controls tree (not blockchain consensus)

---

## 10. Documentation Requirements

### Technical Documentation

1. **Architecture doc:** Explain Merkle tree structure and why it matters
2. **API guide:** Show how to generate and verify proofs
3. **Crypto explainer:** Non-technical explanation of guarantees
4. **Diagrams:** Visualize tree structure, proof verification

### README Addition

Add section to project README:

````markdown
## Cryptographically Verifiable Audit

Credo uses a **Merkle tree** to provide tamper-evident audit logging.

### What This Means

- Every audit event becomes a leaf in a binary tree
- The tree's root hash is a cryptographic fingerprint of all events
- Any modification to past events changes the root hash
- You can prove an event exists without revealing all events
- Tampering is cryptographically detectable

### Generate Inclusion Proof

```bash
curl http://localhost:8080/audit/proof/evt_abc123
```
````

### Verify Proof

```bash
curl -X POST http://localhost:8080/audit/verify-proof -d '{...}'
```

### Use Cases

- Prove to auditors that logs haven't been tampered
- Provide cryptographic proof of specific events
- Detect unauthorized modifications to audit trail

```

---

## 11. Future Enhancements

- **Incremental tree updates:** O(log n) append instead of O(n) rebuild
- **Persistent tree storage:** Serialize tree to disk/database
- **Timestamping service:** Anchor root hashes to external timestamp authority
- **Blockchain anchoring:** Periodically publish root hash to public blockchain
- **Distributed verification:** Allow multiple parties to verify same tree
- **Zero-knowledge proofs:** Prove properties about events without revealing them
- **Audit log compression:** Archive old subtrees, keep only root hashes

---

### 11.1 Secure Ingestion & Anchoring

- Ingestion validates event signatures/HMACs before adding leaves; unverifiable events are rejected (default deny).
- Merkle roots are anchored periodically to an external trust store (e.g., WORM object storage or public ledger) with retained anchor receipts and rotation schedule.
- Append-only property is enforced with structural checks: no rewriting of historical nodes; rebuilds must recompute and compare against anchored roots.
- Reader/writer interfaces split: `MerkleAppender` (write-only) vs `MerkleVerifier` (read/verify) to enforce least privilege.

## 12. References

- [Merkle Tree (Wikipedia)](https://en.wikipedia.org/wiki/Merkle_tree)
- [Certificate Transparency (RFC 6962)](https://tools.ietf.org/html/rfc6962) - Real-world Merkle tree usage
- [Trillian (Google)](https://github.com/google/trillian) - Production Merkle tree implementation
- Existing Code: `internal/audit/` (PRD-006)

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.1 | 2025-12-18 | Security Eng | Added secure ingestion/anchoring and least-privilege interfaces |
| 1.0 | 2025-12-06 | Engineering Team | Initial PRD |
```
