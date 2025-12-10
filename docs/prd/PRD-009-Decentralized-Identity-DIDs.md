# PRD-009: Decentralized Identity (DIDs)

**Status:** Not Started
**Priority:** P2 (Medium)
**Owner:** Engineering Team
**Last Updated:** 2025-12-06
**Dependencies:** PRD-001 (Authentication), PRD-004 (Verifiable Credentials)

---

## 1. Overview

### Problem Statement

Current system uses centralized identity (email/password, OAuth providers). Users must create separate accounts on each platform, have no control over their identity data, and risk identity loss if a provider shuts down or locks their account. This doesn't align with emerging W3C standards for decentralized, user-controlled identity.

### Goals

- Implement W3C Decentralized Identifiers (DIDs) standard
- Enable users to create self-sovereign identities independent of any provider
- Support multiple DID methods (did:key, did:web, optionally did:ethr)
- Allow users to authenticate using DIDs instead of traditional credentials
- Issue Verifiable Credentials to DID subjects (not just internal IDs)
- Enable DID-based authorization and consent management
- Provide DID resolution and verification
- Support DID document management (key rotation, service endpoints)

### Non-Goals

- Full blockchain integration (use simple methods first)
- Decentralized storage (IPFS, Filecoin) - local storage sufficient
- Social recovery mechanisms
- Multi-signature DIDs
- DID marketplace or reputation system
- Mobile wallet integration (Phase 1)
- Universal resolver integration

---

## 2. User Stories

### As an End User

- I want to create a DID that I control across platforms
- I want to authenticate to services using my DID (not email/password)
- I want to receive Verifiable Credentials issued to my DID
- I want to present credentials from my DID to relying parties
- I want to rotate my DID keys if compromised
- I want to add/remove authentication methods from my DID

### As a Relying Party (Service Provider)

- I want to verify that a user controls a specific DID
- I want to issue Verifiable Credentials to DIDs
- I want to verify credentials presented from DIDs
- I want to request specific credentials from a DID holder
- I want to maintain authorization policies based on DIDs

### As a System Administrator

- I want to support multiple DID methods
- I want to configure which DID methods are trusted
- I want to audit DID-based authentication events
- I want to revoke credentials issued to DIDs
- I want to monitor DID resolution performance

---

## 3. Technical Design

### 3.1 W3C DID Standard Overview

**DID Syntax:**

```
did:method:method-specific-id
```

Examples:

- `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`
- `did:web:example.com`
- `did:ethr:0x1234567890abcdef1234567890abcdef12345678`

**DID Document:**

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [
    {
      "id": "did:key:z6Mk...#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6Mk...",
      "publicKeyMultibase": "z6MkhaX..."
    }
  ],
  "authentication": ["did:key:z6Mk...#key-1"],
  "assertionMethod": ["did:key:z6Mk...#key-1"],
  "service": [
    {
      "id": "did:key:z6Mk...#credo",
      "type": "IdentityGateway",
      "serviceEndpoint": "https://gateway.example.com"
    }
  ]
}
```

### 3.2 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Identity Gateway                         │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         DID Management Layer                         │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │  │
│  │  │   DID      │  │   DID      │  │  DID Key     │  │  │
│  │  │  Creator   │  │  Resolver  │  │  Manager     │  │  │
│  │  └────────────┘  └────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │      DID Method Implementations                      │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │  │
│  │  │ did:key  │  │ did:web  │  │  did:ethr        │  │  │
│  │  │ Handler  │  │ Handler  │  │  Handler (opt)   │  │  │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │        Existing Components (Enhanced)                │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │  │
│  │  │    Auth    │  │    VCs     │  │   Consent    │  │  │
│  │  │  Service   │  │  Service   │  │   Service    │  │  │
│  │  │ (DID auth) │  │(DID-based) │  │ (DID-based)  │  │  │
│  │  └────────────┘  └────────────┘  └──────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
              ┌──────────────────────────────┐
              │     DID Registry (DB)        │
              │  ┌────────────────────────┐  │
              │  │  DID Documents         │  │
              │  │  Key Material          │  │
              │  │  Service Endpoints     │  │
              │  └────────────────────────┘  │
              └──────────────────────────────┘
```

### 3.3 Data Model

**DID Record**

```go
type DIDRecord struct {
    ID              string                 `json:"id"`               // DID string
    Method          string                 `json:"method"`           // "key", "web", "ethr"
    Document        DIDDocument            `json:"document"`         // Full DID document
    ControllerID    string                 `json:"controller_id"`    // Internal user ID
    TenantID        string                 `json:"tenant_id"`
    CreatedAt       time.Time              `json:"created_at"`
    UpdatedAt       time.Time              `json:"updated_at"`
    DeactivatedAt   *time.Time             `json:"deactivated_at,omitempty"`
    Metadata        map[string]interface{} `json:"metadata"`
}

type DIDDocument struct {
    Context              []string              `json:"@context"`
    ID                   string                `json:"id"`
    Controller           []string              `json:"controller,omitempty"`
    VerificationMethod   []VerificationMethod  `json:"verificationMethod"`
    Authentication       []interface{}         `json:"authentication"`       // string or embedded
    AssertionMethod      []interface{}         `json:"assertionMethod"`
    KeyAgreement         []interface{}         `json:"keyAgreement,omitempty"`
    CapabilityInvocation []interface{}         `json:"capabilityInvocation,omitempty"`
    CapabilityDelegation []interface{}         `json:"capabilityDelegation,omitempty"`
    Service              []ServiceEndpoint     `json:"service,omitempty"`
}

type VerificationMethod struct {
    ID                 string `json:"id"`
    Type               string `json:"type"`                // "Ed25519VerificationKey2020", etc.
    Controller         string `json:"controller"`
    PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
    PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
}

type ServiceEndpoint struct {
    ID              string   `json:"id"`
    Type            string   `json:"type"`
    ServiceEndpoint string   `json:"serviceEndpoint"`
}
```

**DID Key Material** (encrypted at rest)

```go
type DIDKeyMaterial struct {
    ID           string    `json:"id"`
    DID          string    `json:"did"`
    KeyID        string    `json:"key_id"`           // Fragment identifier
    KeyType      string    `json:"key_type"`         // "Ed25519", "secp256k1"
    PrivateKey   []byte    `json:"private_key"`      // Encrypted
    PublicKey    []byte    `json:"public_key"`
    Purpose      []string  `json:"purpose"`          // ["authentication", "assertion"]
    CreatedAt    time.Time `json:"created_at"`
    RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}
```

### 3.4 DID Methods Implementation

#### did:key (Primary Method - Phase 1)

- **Description:** Self-contained DIDs derived from public keys
- **Format:** `did:key:z6Mk...` (Multibase-encoded public key)
- **Resolution:** Local (no external lookup needed)
- **Advantages:** Simple, no registry, cryptographically verifiable
- **Disadvantages:** Cannot update keys (immutable)

**Implementation:**

```go
func CreateDIDKey(keyType string) (string, *DIDDocument, *KeyPair, error) {
    // Generate keypair (Ed25519 or secp256k1)
    privateKey, publicKey, err := generateKeyPair(keyType)
    if err != nil {
        return "", nil, nil, err
    }

    // Encode public key as multibase
    multibaseKey := encodeMultibase(publicKey)

    // Construct DID
    did := fmt.Sprintf("did:key:%s", multibaseKey)

    // Generate DID Document
    doc := &DIDDocument{
        Context: []string{"https://www.w3.org/ns/did/v1"},
        ID:      did,
        VerificationMethod: []VerificationMethod{{
            ID:                 fmt.Sprintf("%s#%s", did, multibaseKey),
            Type:               "Ed25519VerificationKey2020",
            Controller:         did,
            PublicKeyMultibase: multibaseKey,
        }},
        Authentication:  []interface{}{fmt.Sprintf("%s#%s", did, multibaseKey)},
        AssertionMethod: []interface{}{fmt.Sprintf("%s#%s", did, multibaseKey)},
    }

    return did, doc, &KeyPair{privateKey, publicKey}, nil
}
```

#### did:web (Phase 2)

- **Description:** DIDs hosted on web servers
- **Format:** `did:web:example.com:users:alice`
- **Resolution:** HTTPS GET to `https://example.com/users/alice/did.json`
- **Advantages:** Updatable, human-readable, uses existing web infrastructure
- **Disadvantages:** Centralized (DNS + HTTPS), relies on domain ownership

**Implementation:**

```go
func ResolveDIDWeb(did string) (*DIDDocument, error) {
    // Parse: did:web:example.com:users:alice
    parts := strings.Split(did, ":")
    if len(parts) < 3 || parts[1] != "web" {
        return nil, errors.New("invalid did:web format")
    }

    // Build URL: https://example.com/users/alice/did.json
    domain := parts[2]
    path := strings.Join(parts[3:], "/")
    url := fmt.Sprintf("https://%s/%s/did.json", domain, path)

    // Fetch DID document
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var doc DIDDocument
    if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
        return nil, err
    }

    return &doc, nil
}
```

#### did:ethr (Optional - Phase 3)

- **Description:** Ethereum-based DIDs
- **Format:** `did:ethr:0x1234...`
- **Resolution:** Ethereum smart contract lookup
- **Advantages:** Decentralized, blockchain-based, updatable
- **Disadvantages:** Requires Ethereum node, gas costs, complexity

### 3.5 API Design

#### Create DID

```http
POST /api/v1/dids
Authorization: Bearer {token}
Content-Type: application/json

{
  "method": "key",
  "key_type": "Ed25519",
  "options": {
    "service_endpoints": [{
      "type": "IdentityGateway",
      "endpoint": "https://gateway.example.com"
    }]
  }
}
```

**Response:**

```json
{
  "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "document": {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:key:z6Mk...",
    "verificationMethod": [
      {
        "id": "did:key:z6Mk...#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:key:z6Mk...",
        "publicKeyMultibase": "z6MkhaX..."
      }
    ],
    "authentication": ["did:key:z6Mk...#key-1"],
    "assertionMethod": ["did:key:z6Mk...#key-1"]
  },
  "created_at": "2025-12-06T10:30:00Z"
}
```

#### Resolve DID

```http
GET /api/v1/dids/{did}
```

**Response:** (DID Document as per W3C spec)

#### Authenticate with DID

```http
POST /api/v1/auth/did/challenge
Content-Type: application/json

{
  "did": "did:key:z6Mk..."
}
```

**Response:**

```json
{
  "challenge": "da2b8f3c-4e5f-6789-0123-456789abcdef",
  "expires_at": "2025-12-06T10:35:00Z"
}
```

**Prove Control:**

```http
POST /api/v1/auth/did/authenticate
Content-Type: application/json

{
  "did": "did:key:z6Mk...",
  "challenge": "da2b8f3c-4e5f-6789-0123-456789abcdef",
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:key:z6Mk...#key-1",
    "proofPurpose": "authentication",
    "created": "2025-12-06T10:30:00Z",
    "proofValue": "z5Q3..."
  }
}
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "did": "did:key:z6Mk..."
}
```

#### Issue Verifiable Credential to DID

```http
POST /api/v1/credentials/issue
Authorization: Bearer {token}
Content-Type: application/json

{
  "subject_did": "did:key:z6Mk...",
  "credential_type": "VerifiedEmail",
  "claims": {
    "email": "alice@example.com",
    "verified_at": "2025-12-06T10:30:00Z"
  }
}
```

**Response:**

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": ["VerifiableCredential", "VerifiedEmailCredential"],
  "issuer": "did:web:gateway.example.com",
  "issuanceDate": "2025-12-06T10:30:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "email": "alice@example.com",
    "verified_at": "2025-12-06T10:30:00Z"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-12-06T10:30:00Z",
    "verificationMethod": "did:web:gateway.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5Q3..."
  }
}
```

#### Update DID Document (did:web only)

```http
PATCH /api/v1/dids/{did}
Authorization: Bearer {token}
Content-Type: application/json

{
  "add_verification_methods": [{
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "z6Mk..."
  }],
  "remove_verification_methods": ["did:web:example.com#old-key"],
  "add_services": [{
    "type": "MessagingService",
    "serviceEndpoint": "https://messages.example.com"
  }]
}
```

### 3.6 Integration with Existing Components

#### Authentication Service

```go
// Support both traditional and DID-based auth
type AuthRequest struct {
    // Traditional
    Email    string `json:"email,omitempty"`
    Password string `json:"password,omitempty"`

    // DID-based
    DID       string     `json:"did,omitempty"`
    Challenge string     `json:"challenge,omitempty"`
    Proof     *DIDProof  `json:"proof,omitempty"`
}

func (s *AuthService) Authenticate(req *AuthRequest) (*Session, error) {
    if req.DID != "" && req.Proof != nil {
        return s.authenticateDID(req)
    }
    return s.authenticateTraditional(req)
}
```

#### Verifiable Credentials

```go
// Enhance VCs to support DID subjects
type VerifiableCredential struct {
    // ... existing fields ...

    // Subject can be internal ID or DID
    CredentialSubject CredentialSubject `json:"credentialSubject"`
}

type CredentialSubject struct {
    ID    string                 `json:"id"`    // Internal ID or DID
    IsDID bool                    `json:"-"`     // Internal flag
    Claims map[string]interface{} `json:",inline"`
}
```

#### Consent Management

```go
// Grant consent using DID
type ConsentGrant struct {
    // ... existing fields ...

    SubjectType string `json:"subject_type"` // "user_id" or "did"
    SubjectID   string `json:"subject_id"`   // User ID or DID
}
```

---

## 4. Implementation Plan

### Phase 1: did:key Foundation (Week 1-2)

- [ ] Implement did:key creation
- [ ] Implement did:key resolution (local)
- [ ] Create DID registry database schema
- [ ] Build DID management API endpoints
- [ ] Add DID-based authentication (challenge-response)
- [ ] Unit tests for cryptographic operations

### Phase 2: VC Integration (Week 3)

- [ ] Enhance VC service to support DID subjects
- [ ] Issue VCs to DIDs
- [ ] Verify VCs from DIDs
- [ ] Update consent management for DIDs
- [ ] Integration tests

### Phase 3: did:web Support (Week 4)

- [ ] Implement did:web creation
- [ ] Implement did:web resolution (HTTPS)
- [ ] Host DID documents on gateway domain
- [ ] Add DID document update operations
- [ ] Key rotation for did:web

### Phase 4: Production Readiness (Week 5-6)

- [ ] Security audit (key storage, challenge generation)
- [ ] Performance optimization (caching DID resolution)
- [ ] Documentation (API guide, DID method guide)
- [ ] Migration path (existing users → DIDs)
- [ ] Admin tools (DID management dashboard)

### Phase 5: Advanced Features (Future)

- [ ] did:ethr support (Ethereum-based)
- [ ] DID deactivation and recovery
- [ ] Service endpoint management
- [ ] Mobile wallet integration
- [ ] DIDComm messaging support

---

## 5. Testing Strategy

### Unit Tests

- DID creation and parsing
- Cryptographic signature generation/verification
- DID document serialization
- Multibase encoding/decoding

### Integration Tests

- End-to-end DID authentication flow
- VC issuance to DIDs
- DID resolution (local and did:web)
- Consent management with DIDs

### Security Tests

- Challenge replay attacks
- Private key protection
- DID hijacking attempts
- Signature forgery resistance

### Interoperability Tests

- W3C DID spec compliance
- Test against reference implementations
- Cross-platform DID resolution

---

## 6. Success Metrics

### Adoption Metrics

- Number of DIDs created
- DID-based authentication usage
- VCs issued to DIDs
- Active DIDs per month

### Technical Metrics

- DID resolution latency (<100ms for did:key, <500ms for did:web)
- Authentication success rate
- Key rotation frequency
- DID document size

### Security Metrics

- Zero private key leaks
- Zero successful DID hijacking attempts
- Challenge reuse detection rate

---

## 7. Security & Privacy Considerations

### Key Management

- Private keys encrypted at rest (AES-256)
- Keys never transmitted over network
- Support for hardware security modules (HSM) - future
- Regular key rotation recommendations
- Secure key deletion on DID deactivation

### Authentication Security

- Challenge must be cryptographically random
- Challenge expires after 5 minutes
- One-time use challenges (no replay)
- Rate limiting on authentication attempts
- Audit all authentication events

### Privacy

- DIDs are pseudonymous (don't contain PII)
- User controls which credentials to present
- Selective disclosure support
- No correlation across services (different DIDs per context)

### DID Document Security

- Integrity verification (signatures on did:web documents)
- HTTPS required for did:web resolution
- Cache validation and expiry
- Protection against DID document injection

---

## 8. Documentation Requirements

### For Developers

- DID method specifications
- API integration guide
- Code examples (create, authenticate, issue VC)
- Cryptographic details

### For End Users

- "What is a DID?" explainer
- How to create and manage DIDs
- DID authentication guide
- Key management best practices

### For Administrators

- DID method configuration
- Key rotation procedures
- DID revocation and recovery
- Compliance considerations

---

## 9. Open Questions

1. **User Experience:** How do non-technical users manage DIDs and keys?

   - Provide simplified "managed DID" option?
   - Integration with browser-based wallets?

2. **Portability:** How do users export/import DIDs across platforms?

   - Support standard formats (JSON, DIDKit)?
   - Encrypted export bundles?

3. **Recovery:** What happens if a user loses their private key?

   - Social recovery?
   - Backup recovery keys?
   - Account recovery service?

4. **Scalability:** How to handle high-volume DID resolution?

   - Caching strategy?
   - CDN for did:web documents?
   - Rate limiting?

5. **Compliance:** How do DIDs interact with KYC/AML requirements?
   - Linkage between DID and verified identity?
   - Compliance-friendly DID methods?

---

## 10. Future Enhancements

- **DIDComm:** Secure peer-to-peer messaging using DIDs
- **Universal Resolver:** Integration with did.io universal resolver
- **Mobile SDK:** Native DID support in mobile apps
- **Hardware Wallets:** Support for Ledger, Trezor
- **did:ion:** Bitcoin-anchored DIDs via ION network
- **Credential Manifests:** Request credentials from holders
- **Presentation Exchange:** Standardized credential presentation protocol

---

## 11. References

- W3C DID Core Specification: https://www.w3.org/TR/did-core/
- W3C Verifiable Credentials: https://www.w3.org/TR/vc-data-model/
- did:key Method Spec: https://w3c-ccg.github.io/did-method-key/
- did:web Method Spec: https://w3c-ccg.github.io/did-method-web/
- did:ethr Registry: https://github.com/decentralized-identity/ethr-did-resolver
- DIF (Decentralized Identity Foundation): https://identity.foundation/
- Multibase Encoding: https://github.com/multiformats/multibase
