# PRD-013: Biometric Verification

**Status:** Not Started
**Priority:** P1 (High - Identity Verification)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-003 (Registry Integration), PRD-005 (Decision Engine)
**Last Updated:** 2025-12-11

---

## 1. Overview

### Problem Statement

Current identity verification relies solely on registry lookups (national ID databases) which:
- Cannot verify physical presence (vulnerable to identity theft)
- Do not confirm the person matches their claimed identity
- Lack real-time liveness detection (susceptible to photo/video spoofing)
- Cannot satisfy KYC/AML requirements for high-risk transactions

Biometric verification adds a critical layer by confirming the person presenting credentials is the legitimate owner through face matching and liveness detection.

### Goals

**V1 (Basic Biometric Integration):**
- Implement 1:1 face matching (compare selfie to document photo)
- Add passive liveness detection (anti-spoofing)
- Integrate biometric scores into decision engine as evidence
- Provide HTTP endpoints for biometric verification
- Apply GDPR Article 9 controls for biometric data

**V2 (Production-Ready Biometrics):**
- Add active liveness detection (challenge-response)
- Support multi-modal biometrics (face + fingerprint)
- Implement biometric template encryption and secure storage
- Add fraud detection (device fingerprinting, behavioral signals)
- Support continuous authentication (session-based re-verification)
- Integrate with third-party biometric providers (Onfido, Jumio, Veriff)

### Non-Goals

- Biometric enrollment for authentication (not replacing passwords)
- 1:N face search (identifying unknown person from database)
- Fingerprint/iris recognition hardware integration (V1)
- Mobile SDK biometric capture (V1 - HTTP API only)
- Biometric encryption at protocol level (TLS sufficient for V1)

---

## 2. User Stories

### V1 Stories

**As a compliance officer**
- I want to verify users with face matching against government ID photos
- So that I can confirm identity for KYC/AML requirements

**As a fraud analyst**
- I want to detect spoofing attempts using liveness detection
- So that I can prevent fraudulent account creation

**As a privacy officer**
- I want biometric data to be minimized and encrypted
- So that I comply with GDPR Article 9 (special category data)

### V2 Stories

**As a risk manager**
- I want to require active liveness for high-risk transactions
- So that I can ensure real-time physical presence

**As a developer**
- I want to integrate with multiple biometric providers
- So that I can choose best-in-class services by region

**As an end user**
- I want biometric verification to complete in <3 seconds
- So that the experience doesn't feel intrusive

---

## 3. Functional Requirements (V1)

### FR-1: Face Match Verification (1:1)

**Endpoint:** `POST /biometric/face/match`

**Description:** Compare two face images (selfie vs. document photo) and return similarity score. This is a 1:1 verification, not a 1:N search.

**Input:**

```json
{
  "selfie_image": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEA...",
  "reference_image": "data:image/jpeg;base64,iVBORw0KGgoAAAANSUhEUgAA...",
  "liveness_required": true,
  "national_id": "123456789"
}
```

**Output (Success - 200):**

```json
{
  "match_result": "MATCH",
  "confidence_score": 0.94,
  "liveness_score": 0.89,
  "liveness_passed": true,
  "fraud_signals": [],
  "verification_id": "biometric_abc123xyz",
  "timestamp": "2025-12-11T10:00:00Z",
  "details": {
    "face_detected": true,
    "quality_score": 0.92,
    "spoofing_detected": false
  }
}
```

**Output (No Match - 200):**

```json
{
  "match_result": "NO_MATCH",
  "confidence_score": 0.34,
  "liveness_score": 0.87,
  "liveness_passed": true,
  "fraud_signals": ["low_similarity"],
  "verification_id": "biometric_def456xyz",
  "timestamp": "2025-12-11T10:00:00Z"
}
```

**Output (Spoofing Detected - 200):**

```json
{
  "match_result": "LIVENESS_FAILED",
  "confidence_score": 0.91,
  "liveness_score": 0.12,
  "liveness_passed": false,
  "fraud_signals": ["screen_capture_detected", "low_liveness_score"],
  "verification_id": "biometric_ghi789xyz",
  "timestamp": "2025-12-11T10:00:00Z"
}
```

**Authentication:**
- Requires valid JWT bearer token
- Token validated via RequireAuth middleware

**Business Logic:**

1. Extract user_id from JWT claims
2. Require consent for `ConsentPurposeBiometricVerification`
3. Validate both images are provided and valid base64-encoded JPEG/PNG
4. **Image Quality Check:**
   - Detect face in both images (reject if no face found)
   - Check image resolution (min 480x640 pixels)
   - Verify image quality score (lighting, blur, angle)
5. **Liveness Detection (Passive):**
   - Analyze selfie for spoofing indicators:
     - Screen capture artifacts
     - Video replay patterns
     - 3D mask detection
     - Moiré patterns
   - Compute liveness score (0.0-1.0)
   - Pass threshold: ≥ 0.70
6. **Face Matching:**
   - Extract facial embeddings from both images
   - Compute cosine similarity between embeddings
   - Confidence score = similarity (0.0-1.0)
   - Match threshold: ≥ 0.85
7. **Result Determination:**
   - If liveness_score < 0.70: `LIVENESS_FAILED`
   - Else if confidence_score ≥ 0.85: `MATCH`
   - Else: `NO_MATCH`
8. **Store Verification Record (Minimal PII):**
   - Save verification_id, user_id, result, scores, timestamp
   - **DO NOT** store raw images (discard after processing)
   - Store only facial embeddings (hashed) for fraud analysis
9. Emit audit event with result
10. Return verification result

**Validation:**
- Both images required
- Images must be valid JPEG/PNG
- Image size limit: 10MB per image
- national_id required if linking to registry record

**Error Cases:**
- 401 Unauthorized: Invalid bearer token
- 403 Forbidden: Missing consent for biometric processing
- 400 Bad Request: Invalid image format or size
- 400 Bad Request: No face detected in image
- 422 Unprocessable Entity: Image quality too low
- 500 Internal Server Error: Biometric engine failure

**Audit Event:**

```json
{
  "action": "biometric_face_match",
  "user_id": "user_123",
  "purpose": "biometric_verification",
  "decision": "match", // or "no_match", "liveness_failed"
  "reason": "kyc_verification",
  "metadata": {
    "confidence_score": 0.94,
    "liveness_score": 0.89,
    "verification_id": "biometric_abc123xyz"
  }
}
```

---

### FR-2: Liveness Check (Standalone)

**Endpoint:** `POST /biometric/liveness`

**Description:** V1 supports passive liveness only (analyze single image for spoofing). V2 will add active liveness (challenge-response).

**Input:**

```json
{
  "image": "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEA..."
}
```

**Output (Success - 200):**

```json
{
  "liveness_result": "LIVE",
  "liveness_score": 0.91,
  "fraud_signals": [],
  "verification_id": "liveness_abc123xyz",
  "timestamp": "2025-12-11T10:00:00Z"
}
```

**Business Logic:**
- Same liveness detection as FR-1, but standalone
- No face matching performed
- Used for pre-screening before document submission

---

### FR-3: Biometric Evidence for Decision Engine

**Function:** `biometricService.GetEvidence(ctx, userID, nationalID)`

**Description:** Internal service method that retrieves the most recent biometric verification for a user and formats it as evidence for the decision engine.

**Usage Example:**

```go
// In decision handler
biometricEvidence, err := h.biometricService.GetEvidence(ctx, userID, nationalID)
if err != nil && !errors.IsNotFound(err) {
    return err
}

decisionInput := decision.DecisionInput{
    UserID:            userID,
    Purpose:           "kyc_verification",
    BiometricEvidence: biometricEvidence, // Can be nil if no verification done
    // ... other evidence
}
```

**Returns:**

```go
type BiometricEvidence struct {
    VerificationID  string
    MatchResult     string  // "MATCH", "NO_MATCH", "LIVENESS_FAILED"
    ConfidenceScore float64
    LivenessScore   float64
    Timestamp       time.Time
    FraudSignals    []string
}
```

**Integration with Decision Engine:**

The decision engine uses biometric evidence as follows:

```go
// In decision.Service.Evaluate()
if input.BiometricEvidence != nil {
    if input.BiometricEvidence.MatchResult == "MATCH" &&
       input.BiometricEvidence.ConfidenceScore >= 0.85 &&
       input.BiometricEvidence.LivenessScore >= 0.70 {
        // High confidence - allow transaction
        return DecisionPass
    } else if input.BiometricEvidence.MatchResult == "LIVENESS_FAILED" {
        // Spoofing detected - hard fail
        return DecisionFail, "spoofing_detected"
    } else {
        // Low confidence - require manual review
        return DecisionPassWithConditions, []string{"manual_review"}
    }
}
```

---

## 4. Technical Requirements (V1)

### TR-1: Data Models

**BiometricVerification** (Location: `internal/biometric/models.go`)

```go
type VerificationResult string

const (
    ResultMatch          VerificationResult = "MATCH"
    ResultNoMatch        VerificationResult = "NO_MATCH"
    ResultLivenessFailed VerificationResult = "LIVENESS_FAILED"
)

type BiometricVerification struct {
    ID              string             // Format: "biometric_<uuid>"
    UserID          string             // Foreign key to User.ID
    NationalID      string             // Optional link to registry record
    MatchResult     VerificationResult
    ConfidenceScore float64            // 0.0-1.0
    LivenessScore   float64            // 0.0-1.0
    LivenessPassed  bool
    FraudSignals    []string           // ["screen_capture_detected", ...]

    // Image metadata (NOT the images themselves)
    SelfieHash      string             // SHA256 of selfie (for deduplication)
    ReferenceHash   string             // SHA256 of reference image

    // Facial embeddings (stored for fraud analysis)
    SelfieEmbedding    []byte          // Encrypted facial embedding vector
    ReferenceEmbedding []byte          // Encrypted facial embedding vector

    // Quality metrics
    QualityScore       float64         // Image quality (0.0-1.0)
    FaceDetected       bool

    CreatedAt       time.Time
    ExpiresAt       time.Time          // Biometric verification valid for 24 hours
}

type BiometricEvidence struct {
    VerificationID  string
    MatchResult     string
    ConfidenceScore float64
    LivenessScore   float64
    Timestamp       time.Time
    FraudSignals    []string
}
```

**ConsentPurpose Addition** (Location: `internal/consent/models.go`)

```go
const (
    // Existing purposes...
    ConsentPurposeBiometricVerification ConsentPurpose = "biometric_verification"
)
```

### TR-2: Biometric Engine Interface

**V1: Mock Biometric Engine** (Location: `internal/biometric/engine.go`)

```go
type BiometricEngine interface {
    // Face matching
    CompareFaces(ctx context.Context, selfie, reference []byte) (*FaceMatchResult, error)

    // Liveness detection
    DetectLiveness(ctx context.Context, image []byte) (*LivenessResult, error)

    // Extract facial embeddings
    ExtractEmbedding(ctx context.Context, image []byte) ([]float64, error)
}

type FaceMatchResult struct {
    ConfidenceScore float64
    QualityScore    float64
    FaceDetected    bool
}

type LivenessResult struct {
    LivenessScore   float64
    FraudSignals    []string
    SpoofingDetails map[string]interface{}
}

// MockBiometricEngine for V1
type MockBiometricEngine struct {
    latency time.Duration // Simulated processing time
}

func (e *MockBiometricEngine) CompareFaces(ctx context.Context, selfie, reference []byte) (*FaceMatchResult, error) {
    // V1: Deterministic mock based on image hash
    // Hash both images and compute similarity
    // Return confidence score between 0.3-0.98

    time.Sleep(e.latency) // Simulate processing (200-500ms)

    // Simple hash-based similarity
    selfieHash := sha256.Sum256(selfie)
    refHash := sha256.Sum256(reference)

    // XOR hashes and count matching bits to simulate similarity
    similarity := computeSimilarity(selfieHash[:], refHash[:])

    return &FaceMatchResult{
        ConfidenceScore: similarity,
        QualityScore:    0.92,
        FaceDetected:    true,
    }, nil
}

func (e *MockBiometricEngine) DetectLiveness(ctx context.Context, image []byte) (*LivenessResult, error) {
    time.Sleep(e.latency / 2)

    // Hash-based liveness score (deterministic for testing)
    hash := sha256.Sum256(image)
    livenessScore := float64(hash[0]) / 255.0 * 0.7 + 0.3 // Range: 0.3-1.0

    fraudSignals := []string{}
    if livenessScore < 0.70 {
        fraudSignals = append(fraudSignals, "low_liveness_score")
        if livenessScore < 0.50 {
            fraudSignals = append(fraudSignals, "screen_capture_detected")
        }
    }

    return &LivenessResult{
        LivenessScore: livenessScore,
        FraudSignals:  fraudSignals,
    }, nil
}
```

**V2: Production Engines** (Future)

```go
// Third-party integrations
type OnfidoBiometricEngine struct { /* Onfido SDK integration */ }
type JumioBiometricEngine struct { /* Jumio API integration */ }
type VeriffBiometricEngine struct { /* Veriff API integration */ }

// Self-hosted ML models
type TensorFlowBiometricEngine struct { /* TensorFlow Serving integration */ }
type FaceRecognitionEngine struct { /* face_recognition Python library via gRPC */ }
```

### TR-3: Storage Interface

**BiometricStore** (Location: `internal/biometric/store.go`)

```go
type Store interface {
    Save(ctx context.Context, verification *BiometricVerification) error
    FindByID(ctx context.Context, id string) (*BiometricVerification, error)
    FindLatestByUser(ctx context.Context, userID string) (*BiometricVerification, error)
    FindByUserAndNationalID(ctx context.Context, userID, nationalID string) (*BiometricVerification, error)
    DeleteByUser(ctx context.Context, userID string) error // GDPR deletion
}
```

**Implementation:** `internal/biometric/store_memory.go` (V1)

```go
type InMemoryStore struct {
    mu            sync.RWMutex
    verifications map[string]*BiometricVerification  // keyed by ID
    userIndex     map[string][]*BiometricVerification // keyed by UserID
}
```

### TR-4: Service Layer

**BiometricService** (Location: `internal/biometric/service.go`)

```go
type Service struct {
    engine        BiometricEngine
    store         Store
    auditor       audit.Publisher

    // Configuration
    matchThreshold    float64 // Default: 0.85
    livenessThreshold float64 // Default: 0.70
    ttl               time.Duration // Verification validity: 24h
}

// V1 Methods
func (s *Service) VerifyFaceMatch(ctx context.Context, req *FaceMatchRequest) (*BiometricVerification, error)
func (s *Service) CheckLiveness(ctx context.Context, image []byte) (*LivenessResult, error)
func (s *Service) GetEvidence(ctx context.Context, userID, nationalID string) (*BiometricEvidence, error)

// V2 Methods (Future)
func (s *Service) VerifyActiveLiveness(ctx context.Context, req *ActiveLivenessRequest) (*LivenessResult, error)
func (s *Service) VerifyFingerprint(ctx context.Context, req *FingerprintRequest) (*BiometricVerification, error)
```

### TR-5: HTTP Handlers

**Handler Functions** (Location: `internal/transport/http/handlers_biometric.go`)

```go
func (h *Handler) handleBiometricFaceMatch(w http.ResponseWriter, r *http.Request)
func (h *Handler) handleBiometricLiveness(w http.ResponseWriter, r *http.Request)
```

### TR-6: Data Privacy & Minimization

**GDPR Article 9 Compliance:**

```go
// MinimizeBiometricData ensures no raw biometric data is persisted
func MinimizeBiometricData(verification *BiometricVerification, regulatedMode bool) *BiometricVerification {
    if !regulatedMode {
        return verification
    }

    // In regulated mode:
    // - Embeddings are encrypted (already done during Save)
    // - Image hashes kept for deduplication only
    // - Expire verification after 24 hours
    // - Delete embeddings after verification used in decision

    return verification
}

// DeleteBiometricData removes all biometric data on user deletion
func (s *Service) DeleteBiometricData(ctx context.Context, userID string) error {
    // GDPR Article 17 - Right to erasure
    return s.store.DeleteByUser(ctx, userID)
}
```

---

## 5. Implementation Plan

### V1: Basic Biometric Integration (8-12 hours)

#### Phase 1: Service Layer (3-4 hours)

1. Implement `MockBiometricEngine`:
   - Hash-based face matching simulation
   - Hash-based liveness detection
   - Deterministic scores for testing
2. Implement `BiometricService`:
   - `VerifyFaceMatch()` orchestration
   - `CheckLiveness()` standalone
   - `GetEvidence()` for decision engine
3. Add audit event emission

#### Phase 2: HTTP Handlers (2-3 hours)

1. Implement `handleBiometricFaceMatch`:
   - Parse base64 images
   - Validate image format and size
   - Call service methods
   - Return structured response
2. Implement `handleBiometricLiveness`:
   - Similar to face match but simpler

#### Phase 3: Integration (2-3 hours)

1. Add biometric evidence to decision engine:
   - Update `DecisionInput` struct
   - Add biometric scoring logic
   - Integrate with existing registry/VC evidence
2. Update consent system:
   - Add `ConsentPurposeBiometricVerification`
   - Enforce consent in biometric handlers
3. Wire up in `main.go`

#### Phase 4: Testing (1-2 hours)

1. Unit tests for service methods
2. Integration tests for HTTP endpoints
3. Manual testing with base64-encoded test images
4. Decision engine integration tests

---

### V2: Production-Ready Biometrics (14-18 hours)

#### Phase 1: Active Liveness (4-5 hours)

1. Implement challenge-response liveness:
   - Generate random challenges (smile, turn head, blink)
   - Capture video stream
   - Analyze compliance with challenge
2. Add `POST /biometric/liveness/challenge` and `/biometric/liveness/verify` endpoints

#### Phase 2: Third-Party Integration (5-6 hours)

1. Abstract biometric engine:
   - Create provider interface
   - Implement Onfido adapter
   - Implement Jumio adapter
   - Add provider selection logic
2. Configuration for provider selection:
   - Environment variable: `BIOMETRIC_PROVIDER=onfido`
   - Fallback chain: Onfido → Jumio → Mock

#### Phase 3: Multi-Modal Biometrics (3-4 hours)

1. Add fingerprint verification:
   - `POST /biometric/fingerprint/match`
   - Combine face + fingerprint scores
2. Update decision engine for multi-factor biometric evidence

#### Phase 4: Security & Performance (2-3 hours)

1. Implement biometric template encryption:
   - Encrypt embeddings at rest
   - Use separate KEK for biometric data
2. Add rate limiting:
   - Max 10 verifications per user per hour
   - Prevent brute-force attacks
3. Performance optimization:
   - Cache embeddings for recent verifications
   - Parallel processing for multi-image requests

---

## 6. API Specifications

### Endpoint Summary (V1)

| Endpoint                   | Method | Auth Required | Consent Required          | Purpose                |
| -------------------------- | ------ | ------------- | ------------------------- | ---------------------- |
| `/biometric/face/match`    | POST   | Yes           | `biometric_verification`  | 1:1 face matching      |
| `/biometric/liveness`      | POST   | Yes           | `biometric_verification`  | Liveness check         |

### Endpoint Summary (V2)

| Endpoint                            | Method | Auth Required | Consent Required          | Purpose                      |
| ----------------------------------- | ------ | ------------- | ------------------------- | ---------------------------- |
| `/biometric/liveness/challenge`     | POST   | Yes           | `biometric_verification`  | Start active liveness        |
| `/biometric/liveness/verify`        | POST   | Yes           | `biometric_verification`  | Complete active liveness     |
| `/biometric/fingerprint/match`      | POST   | Yes           | `biometric_verification`  | Fingerprint verification     |
| `/biometric/verification/{id}`      | GET    | Yes           | None                      | Retrieve verification result |

### Image Format Requirements

**Supported Formats:** JPEG, PNG
**Encoding:** Base64 data URI (e.g., `data:image/jpeg;base64,...`)
**Size Limits:**
- Min resolution: 480x640 pixels
- Max file size: 10MB
- Recommended: 720x960 pixels for optimal quality

**Quality Requirements:**
- Face must be clearly visible (not obscured)
- Adequate lighting (not too dark or bright)
- Frontal face (max 15-degree angle deviation)
- No sunglasses or face masks

---

## 7. Security Requirements

### SR-1: Biometric Data Protection (GDPR Article 9)

**Special Category Data:**
- Biometric data is "special category" under GDPR Article 9
- Requires explicit consent (separate from regular data processing)
- Must be encrypted at rest and in transit
- Retention limited to 24 hours after verification
- Immediate deletion on user request

**Implementation:**

```go
// Explicit biometric consent required
err := h.consentService.Require(ctx, userID, consent.ConsentPurposeBiometricVerification)
if err != nil {
    return errors.NewGatewayError(errors.CodeMissingConsent,
        "Biometric processing requires explicit consent (GDPR Article 9)", err)
}

// Encrypt embeddings before storage
encrypted := encryptEmbedding(embedding, biometricKEK)
verification.SelfieEmbedding = encrypted

// Auto-expire after 24 hours
verification.ExpiresAt = time.Now().Add(24 * time.Hour)
```

### SR-2: Anti-Spoofing

**Passive Liveness (V1):**
- Screen capture detection
- Video replay detection
- 3D mask detection
- Moiré pattern analysis

**Active Liveness (V2):**
- Random challenges (smile, blink, turn head)
- Video stream analysis
- Challenge compliance verification
- Presentation attack detection (PAD)

### SR-3: Fraud Prevention

**Rate Limiting:**
- Max 10 verifications per user per hour
- Max 3 failed attempts before lockout (15 min cooldown)
- IP-based rate limiting (100 requests/hour)

**Anomaly Detection:**
- Same selfie used for multiple identities (hash deduplication)
- Rapid repeated verifications (bot detection)
- Device fingerprinting (detect emulators)

### SR-4: Audit & Compliance

**Audit Events:**
- Every biometric verification logged
- Include: user_id, result, scores, timestamp
- NO raw images in audit logs
- Fraud signals included for investigation

**Retention:**
- Verification records: 90 days
- Audit logs: 7 years (compliance requirement)
- Raw embeddings: Deleted after 24 hours
- Image hashes: Retained for fraud analysis (90 days)

---

## 8. Performance Requirements

### PR-1: Latency (V1)

- Face matching: <2 seconds p95
- Liveness check: <1 second p95
- Combined verification: <3 seconds p95

### PR-2: Throughput (V1)

- Target: 100 verifications/minute (single instance)
- Horizontal scaling supported via stateless design

### PR-3: Accuracy (V1 - Mock)

Mock engine provides deterministic results for testing:
- Match threshold: 0.85 (85% similarity)
- Liveness threshold: 0.70 (70% confidence)
- False Accept Rate (FAR): <1% (simulated)
- False Reject Rate (FRR): <5% (simulated)

### PR-4: Production Accuracy (V2)

With real biometric engines:
- FAR: <0.01% (1 in 10,000 false accepts)
- FRR: <1% (1 in 100 false rejects)
- Liveness PAD: >95% detection rate

---

## 9. Testing Requirements

### Unit Tests (V1)

- [ ] Test mock engine face matching (deterministic scores)
- [ ] Test mock engine liveness detection
- [ ] Test image quality validation
- [ ] Test consent enforcement
- [ ] Test embedding encryption
- [ ] Test verification expiry (24h TTL)
- [ ] Test GDPR deletion

### Integration Tests (V1)

- [ ] Test complete face match flow (match result)
- [ ] Test complete face match flow (no match result)
- [ ] Test liveness failure flow
- [ ] Test biometric evidence in decision engine
- [ ] Test consent required (403 without consent)
- [ ] Test image format validation errors

### Manual Testing (V1)

```bash
# 1. Grant biometric consent
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "purposes": ["biometric_verification"]
  }'

# 2. Face match verification (success case)
# Prepare two test images as base64
SELFIE_BASE64=$(base64 -i test_data/selfie.jpg | tr -d '\n')
REFERENCE_BASE64=$(base64 -i test_data/id_photo.jpg | tr -d '\n')

curl -X POST http://localhost:8080/biometric/face/match \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"selfie_image\": \"data:image/jpeg;base64,${SELFIE_BASE64}\",
    \"reference_image\": \"data:image/jpeg;base64,${REFERENCE_BASE64}\",
    \"liveness_required\": true,
    \"national_id\": \"123456789\"
  }"

# Expected: {"match_result": "MATCH", "confidence_score": 0.94, ...}

# 3. Liveness check (standalone)
curl -X POST http://localhost:8080/biometric/liveness \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"image\": \"data:image/jpeg;base64,${SELFIE_BASE64}\"
  }"

# Expected: {"liveness_result": "LIVE", "liveness_score": 0.91, ...}

# 4. Test without consent (should fail)
curl -X POST http://localhost:8080/auth/consent/revoke \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"purposes": ["biometric_verification"]}'

curl -X POST http://localhost:8080/biometric/face/match \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"selfie_image\": \"data:image/jpeg;base64,${SELFIE_BASE64}\",
    \"reference_image\": \"data:image/jpeg;base64,${REFERENCE_BASE64}\"
  }"

# Expected: 403 Forbidden {"error": "missing_consent", ...}
```

---

## 10. Acceptance Criteria

### V1 Acceptance Criteria

- [ ] Face match endpoint returns match/no_match/liveness_failed results
- [ ] Liveness detection scores selfies for spoofing indicators
- [ ] Biometric evidence integrates with decision engine
- [ ] GDPR Article 9 consent required before biometric processing
- [ ] Raw images NOT stored (only hashes and encrypted embeddings)
- [ ] Verifications expire after 24 hours
- [ ] User data deletion removes all biometric records
- [ ] Audit events logged for all verifications
- [ ] Mock engine provides deterministic results for testing
- [ ] Code passes `make test` and `make lint`

### V2 Acceptance Criteria (Future)

- [ ] Active liveness challenge-response implemented
- [ ] Integration with at least one third-party provider (Onfido/Jumio)
- [ ] Multi-modal biometrics (face + fingerprint)
- [ ] Rate limiting prevents brute-force attacks
- [ ] Device fingerprinting detects emulators
- [ ] Fraud detection flags repeated selfie usage
- [ ] Performance: <2s p95 latency for face match
- [ ] Accuracy: <0.01% FAR, <1% FRR with production engines

---

## 11. Dependencies & Blockers

### Dependencies

- PRD-001: Authentication (for user extraction from JWT)
- PRD-002: Consent Management (for biometric consent)
- PRD-003: Registry Integration (for linking biometric to national ID)
- PRD-005: Decision Engine (for biometric evidence integration)
- `internal/audit` - ✅ Already implemented

### Potential Blockers

- **V1:** None (mock engine requires no external dependencies)
- **V2:** Third-party API keys (Onfido, Jumio) and SDK integration

---

## 12. Future Enhancements (V2+)

### Production Features

- **Active Liveness Detection** (challenge-response)
- **Third-Party Integrations** (Onfido, Jumio, Veriff, ID.me)
- **Multi-Modal Biometrics** (face + fingerprint + voice)
- **Continuous Authentication** (periodic re-verification during session)
- **Behavioral Biometrics** (typing patterns, mouse movements)
- **Device Fingerprinting** (detect emulators, root/jailbreak)
- **Fraud Consortium** (share fraud signals across organizations)

### Advanced Capabilities

- **1:N Face Search** (identify unknown person from database)
- **Age Estimation** (estimate age from selfie without date of birth)
- **Emotion Detection** (detect stress/nervousness during verification)
- **Document Liveness** (verify ID document is physical, not a photo)
- **Biometric Deduplication** (find duplicate accounts using face matching)

### Mobile SDK

- **iOS Biometric SDK** (Face ID / Touch ID integration)
- **Android Biometric SDK** (BiometricPrompt API)
- **React Native Module** (cross-platform biometric capture)
- **Flutter Plugin** (biometric verification widget)

---

## 13. Regulatory Considerations

### GDPR Compliance (Article 9)

- ✅ Biometric data classified as "special category"
- ✅ Explicit consent required (separate from regular consent)
- ✅ Encrypted at rest and in transit
- ✅ Minimized retention (24 hours)
- ✅ Right to erasure (delete on user request)
- ✅ Audit trail for all processing

### KYC/AML Compliance

- ✅ Face matching satisfies identity verification requirements
- ✅ Liveness detection prevents fraudulent documents
- ✅ Biometric scores strengthen risk assessment
- ✅ Audit logs provide evidence for regulators

### ISO/IEC 30107 (Presentation Attack Detection)

- ✅ Passive liveness detection (V1)
- ⏳ Active liveness detection (V2)
- ⏳ PAD Level 1 compliance (V2)
- ⏳ PAD Level 2 compliance (V3)

---

## 14. References

- [GDPR Article 9: Processing of special categories of personal data](https://gdpr-info.eu/art-9-gdpr/)
- [ISO/IEC 30107: Biometric presentation attack detection](https://www.iso.org/standard/53227.html)
- [NIST FRVT: Face Recognition Vendor Test](https://pages.nist.gov/frvt/)
- [W3C WebAuthn: Biometric authenticators](https://www.w3.org/TR/webauthn/)
- Onfido API Documentation: https://documentation.onfido.com/
- Jumio API Documentation: https://docs.jumio.com/

---

## Revision History

| Version | Date       | Author           | Changes                                      |
| ------- | ---------- | ---------------- | -------------------------------------------- |
| 1.0     | 2025-12-11 | Engineering Team | Initial PRD - V1 (mock) and V2 (production)  |
