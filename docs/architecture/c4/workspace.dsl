workspace "Credo Identity Verification Gateway" {

    model {
        # ==========================================================================
        # EXTERNAL ACTORS
        # ==========================================================================

        endUser = person "End User" "A user who authenticates and manages consent via browser or mobile app" "Person"
        oauthClient = softwareSystem "OAuth Client" "External applications that integrate with Credo via OAuth 2.0" "External System"
        adminOperator = person "Admin Operator" "System administrator who manages tenants, clients, and monitors the system" "Person"

        # ==========================================================================
        # EXTERNAL SYSTEMS
        # ==========================================================================

        citizenRegistry = softwareSystem "Citizen Registry" "Government citizen identity verification API" "External System"
        sanctionsRegistry = softwareSystem "Sanctions Registry" "PEP and sanctions screening API" "External System"
        observability = softwareSystem "Observability Stack" "Prometheus, Grafana for metrics and monitoring" "External System"

        # ==========================================================================
        # CREDO SYSTEM
        # ==========================================================================

        credo = softwareSystem "Credo" "Identity Verification Gateway - modular monolith with hexagonal architecture" {

            # ----------------------------------------------------------------------
            # HTTP Servers (Entry Points)
            # ----------------------------------------------------------------------

            publicAPI = container "Public API Server" "Handles OAuth 2.0 flows, consent, registry lookups, and VC issuance" "Go, Chi, Port 8080" "API Gateway" {
                requestMiddleware = component "Request Middleware" "Recovery, RequestID, Logger, Timeout, ContentType, BodyLimit" "Go Middleware" "Middleware"
                deviceMiddleware = component "Device Middleware" "Device fingerprinting and cookie management" "Go Middleware" "Middleware"
                metadataMiddleware = component "Metadata Middleware" "Request metadata extraction" "Go Middleware" "Middleware"
                rateLimitMiddleware = component "Rate Limit Middleware" "Per-IP and per-client rate limiting" "Go Middleware" "Middleware"
                authMiddleware = component "Auth Middleware" "JWT validation and session binding" "Go Middleware" "Middleware"
            }

            adminAPI = container "Admin API Server" "Administrative operations, tenant management, monitoring" "Go, Chi, Port 8081" "API Gateway" {
                adminRequestMiddleware = component "Request Middleware" "Recovery, RequestID, Logger, Timeout" "Go Middleware" "Middleware"
                adminTokenMiddleware = component "Admin Token Middleware" "X-Admin-Token header validation" "Go Middleware" "Middleware"
                adminRateLimitMiddleware = component "Admin Rate Limit Middleware" "Admin endpoint rate limiting" "Go Middleware" "Middleware"
            }

            # ----------------------------------------------------------------------
            # AUTH MODULE
            # ----------------------------------------------------------------------

            authModule = container "Auth Module" "OAuth 2.0 authorization server, sessions, device binding" "Go" "Domain Module" {
                authHandler = component "Auth Handler" "HTTP handlers for /auth/* endpoints" "Go" "Handler"
                authService = component "Auth Service" "OAuth 2.0 flows: authorize, token exchange, refresh, revoke" "Go" "Service"
                userStore = component "User Store" "User account persistence" "In-Memory" "Store"
                sessionStore = component "Session Store" "OAuth session persistence" "In-Memory" "Store"
                authCodeStore = component "Authorization Code Store" "OAuth authorization code persistence" "In-Memory" "Store"
                refreshTokenStore = component "Refresh Token Store" "Refresh token persistence" "In-Memory" "Store"
                revocationStore = component "Token Revocation List" "JTI-based token revocation tracking" "In-Memory" "Store"
                deviceService = component "Device Service" "Device fingerprinting and binding" "Go" "Service"
                cleanupWorker = component "Cleanup Worker" "Background job for expired token/session cleanup" "Go" "Worker"

                # Ports (interfaces this module depends on)
                authRateLimitPort = component "RateLimitPort" "CheckAuthRateLimit(identifier, ip)\nRecordAuthFailure(identifier, ip)\nClearAuthFailures(identifier, ip)" "Interface" "Port"
                authClientResolver = component "ClientResolver" "ResolveClient(clientID) → (Client, Tenant)" "Interface" "Port"
                authAuditPublisher = component "AuditPublisher" "Emit(event)" "Interface" "Port"

                # Adapter implementing ports
                rateLimitAdapter = component "Rate Limit Adapter" "Implements RateLimitPort → calls RateLimit module" "Go" "Adapter"
            }

            # ----------------------------------------------------------------------
            # CONSENT MODULE
            # ----------------------------------------------------------------------

            consentModule = container "Consent Module" "Purpose-based consent lifecycle management" "Go" "Domain Module" {
                consentHandler = component "Consent Handler" "HTTP handlers for consent endpoints" "Go" "Handler"
                consentService = component "Consent Service" "Grant, require, revoke consent with idempotency windows" "Go" "Service"
                consentStore = component "Consent Store" "Consent record persistence" "In-Memory" "Store"

                # Domain Model
                consentAggregate = component "Consent" "Domain aggregate with states: pending → granted ↔ revoked\nGrant(), Revoke(), IsActive()" "Domain Model" "Aggregate"
            }

            # ----------------------------------------------------------------------
            # REGISTRY MODULE (Evidence/Registry)
            # ----------------------------------------------------------------------

            registryModule = container "Registry Module" "Multi-provider citizen and sanctions lookups" "Go" "Domain Module" {
                registryHandler = component "Registry Handler" "HTTP handler for /registry/check endpoint" "Go" "Handler"
                registryService = component "Registry Service" "Orchestrates lookups, caching, PII minimization" "Go" "Service"
                registryCache = component "Registry Cache" "TTL-based cache for registry records" "In-Memory" "Store"
                orchestrator = component "Orchestrator" "Multi-provider coordination with fallback strategies" "Go" "Service"
                providerRegistry = component "Provider Registry" "Registry of available providers" "Go" "Service"
                citizenProvider = component "Citizen Provider" "HTTP adapter for citizen registry API" "Go, HTTP Client" "Adapter"
                sanctionsProvider = component "Sanctions Provider" "HTTP adapter for sanctions registry API" "Go, HTTP Client" "Adapter"

                # Ports
                registryConsentPort = component "ConsentPort" "RequireConsent(userID, purpose)" "Interface" "Port"

                # Adapters
                registryConsentAdapter = component "Consent Adapter" "Implements ConsentPort → calls Consent module" "Go" "Adapter"

                # Domain Model
                citizenRecord = component "CitizenRecord" "Valid, NationalID, DateOfBirth (PII stripped in regulated mode)" "Domain Model" "Aggregate"
                sanctionsRecord = component "SanctionsRecord" "IsMatch, MatchType, Confidence" "Domain Model" "Aggregate"
            }

            # ----------------------------------------------------------------------
            # VC MODULE (Evidence/VC)
            # ----------------------------------------------------------------------

            vcModule = container "VC Module" "Verifiable Credential issuance for age verification" "Go" "Domain Module" {
                vcHandler = component "VC Handler" "HTTP handler for /credentials endpoint" "Go" "Handler"
                vcService = component "VC Service" "Issues age-over-18 credentials after verification" "Go" "Service"
                vcStore = component "VC Store" "Credential record persistence" "In-Memory" "Store"

                # Ports
                vcConsentPort = component "ConsentPort" "RequireConsent(userID, purpose)" "Interface" "Port"
                vcRegistryPort = component "RegistryPort" "Citizen(userID, nationalID) → CitizenRecord" "Interface" "Port"

                # Adapters
                vcConsentAdapter = component "Consent Adapter" "Implements ConsentPort → calls Consent module" "Go" "Adapter"
                vcRegistryAdapter = component "Registry Adapter" "Implements RegistryPort → calls Registry module" "Go" "Adapter"

                # Domain Model
                credentialRecord = component "CredentialRecord" "Type, Subject, Claims, IssuedAt, ExpiresAt\nIsExpired(), CredentialType enum" "Domain Model" "Aggregate"
            }

            # ----------------------------------------------------------------------
            # DECISION MODULE
            # ----------------------------------------------------------------------

            decisionModule = container "Decision Module" "Rules engine combining evidence and consent" "Go" "Domain Module" {
                decisionService = component "Decision Service" "Evaluates pass/fail/conditions based on derived identity" "Go" "Service"

                # Ports
                decisionConsentPort = component "ConsentPort" "RequireConsent(userID, purpose)" "Interface" "Port"
                decisionRegistryPort = component "RegistryPort" "CheckCitizen(userID, nationalID)\nCheckSanctions(userID, nationalID)" "Interface" "Port"
                decisionVCPort = component "VCPort" "FindBySubjectAndType(userID, credType)" "Interface" "Port"

                # Adapters
                decisionConsentAdapter = component "Consent Adapter" "Implements ConsentPort → calls Consent module" "Go" "Adapter"
                decisionRegistryAdapter = component "Registry Adapter" "Implements RegistryPort → calls Registry module" "Go" "Adapter"
                decisionVCAdapter = component "VC Adapter" "Implements VCPort → calls VC module" "Go" "Adapter"

                # Domain Model
                decisionResult = component "DecisionResult" "Pass | Fail | ConsentRequired | ConditionsApply\nEvaluate(evidence, consent) → Result" "Domain Model" "Aggregate"
            }

            # ----------------------------------------------------------------------
            # RATE LIMIT MODULE
            # ----------------------------------------------------------------------

            ratelimitModule = container "Rate Limit Module" "Per-IP, per-client, global rate limiting with sliding windows" "Go" "Domain Module" {
                limiter = component "Limiter" "Composes request limit and global throttle services" "Go" "Service"
                requestLimitService = component "Request Limit Service" "Per-IP/user sliding window rate limiting" "Go" "Service"
                authLockoutService = component "Auth Lockout Service" "Brute-force protection for authentication" "Go" "Service"
                globalThrottleService = component "Global Throttle Service" "System-wide DDoS protection" "Go" "Service"
                clientLimitService = component "Client Limit Service" "Per-client (confidential vs public) rate limiting" "Go" "Service"

                # Store Ports (interfaces)
                bucketStorePort = component "BucketStore" "Allow(key, limit, window) → RateLimitResult\nAllowN(key, cost, limit, window)\nReset(key)" "Interface" "Port"
                allowlistStorePort = component "AllowlistStore" "IsAllowlisted(identifier) → bool\nAdd(entry), Remove(type, id)" "Interface" "Port"
                authLockoutStorePort = component "AuthLockoutStore" "GetOrCreate(identifier)\nRecordFailureAtomic(identifier)\nApplyHardLockAtomic(identifier, until)" "Interface" "Port"
                globalThrottleStorePort = component "GlobalThrottleStore" "IncrementGlobal() → (count, blocked)\nGetGlobalCount()" "Interface" "Port"
                clientLookupPort = component "ClientLookup" "IsConfidentialClient(clientID) → bool" "Interface" "Port"

                # Store implementations
                bucketStore = component "Bucket Store" "In-memory sliding window counter" "In-Memory" "Store"
                allowlistStore = component "Allowlist Store" "In-memory bypass entries" "In-Memory" "Store"
                authLockoutStore = component "Auth Lockout Store" "In-memory failure tracking" "In-Memory" "Store"
                globalThrottleStore = component "Global Throttle Store" "In-memory global counter" "In-Memory" "Store"

                # Domain Models
                rateLimitResult = component "RateLimitResult" "Allowed, Remaining, RetryAfter\nIsBlocked()" "Domain Model" "Aggregate"
                authLockout = component "AuthLockout" "FailureCount, LockedUntil, RequiresCaptcha\nIsLocked(now), ShouldApplyHardLock()" "Domain Model" "Aggregate"
            }

            # ----------------------------------------------------------------------
            # TENANT MODULE
            # ----------------------------------------------------------------------

            tenantModule = container "Tenant Module" "Multi-tenancy and OAuth 2.0 client management" "Go" "Domain Module" {
                tenantHandler = component "Tenant Handler" "HTTP handlers for /tenants and /clients endpoints" "Go" "Handler"
                tenantService = component "Tenant Service" "Tenant and client CRUD, client type resolution" "Go" "Service"

                # Store Ports
                tenantStorePort = component "TenantStore" "CreateIfNameAvailable(tenant)\nFindByID(id), FindByName(name)" "Interface" "Port"
                clientStorePort = component "ClientStore" "Create(client), FindByID(id)\nFindByOAuthClientID(oauthID)" "Interface" "Port"
                userCounterPort = component "UserCounter" "CountByTenant(tenantID) → int" "Interface" "Port"

                # Store implementations
                tenantStore = component "Tenant Store" "In-memory tenant persistence" "In-Memory" "Store"
                clientStore = component "Client Store" "In-memory OAuth client persistence" "In-Memory" "Store"

                # Domain Models
                tenantAggregate = component "Tenant" "ID, Name, Settings, CreatedAt\nIsActive()" "Domain Model" "Aggregate"
                clientAggregate = component "Client" "ID, TenantID, Type, RedirectURIs, Secret\nIsConfidential(), ValidateRedirectURI()" "Domain Model" "Aggregate"
            }

            # ----------------------------------------------------------------------
            # ADMIN MODULE
            # ----------------------------------------------------------------------

            adminModule = container "Admin Module" "Administrative queries and statistics" "Go" "Domain Module" {
                adminHandler = component "Admin Handler" "HTTP handlers for /admin/* endpoints" "Go" "Handler"
                adminService = component "Admin Service" "Read-only admin queries (stats, user info, sessions)" "Go" "Service"

                # Ports (read-only views into other modules)
                adminUserStore = component "UserStore" "ListAll() → map[UserID]*User\nFindByID(userID)" "Interface" "Port"
                adminSessionStore = component "SessionStore" "ListAll() → map[SessionID]*Session\nListByUser(userID)" "Interface" "Port"
            }

            # ----------------------------------------------------------------------
            # PLATFORM MODULE (Cross-cutting)
            # ----------------------------------------------------------------------

            platformModule = container "Platform Module" "Cross-cutting infrastructure concerns" "Go" "Infrastructure" {
                configLoader = component "Config Loader" "Environment-based configuration loading" "Go" "Infrastructure"
                logger = component "Logger" "Structured slog-based logging" "Go" "Infrastructure"
                jwtService = component "JWT Service" "Token signing and validation" "Go, HMAC-SHA256" "Service"
                metricsRegistry = component "Metrics Registry" "Prometheus metrics collection" "Go, Prometheus" "Infrastructure"

                # Audit subsystem
                auditPublisherPort = component "AuditPublisher" "Emit(event) error\nUsed by all domain modules" "Interface" "Port"
                auditPublisher = component "Audit Publisher Impl" "Tri-publisher: Sync + Async + Metrics" "Go" "Service"
                auditStore = component "Audit Store" "Audit event persistence (outbox-backed)" "PostgreSQL" "Store"

                # Domain Model
                auditEvent = component "AuditEvent" "Type, Actor, Resource, Timestamp, Metadata\nEventType enum: auth.*, consent.*, registry.*" "Domain Model" "Aggregate"
            }
        }

        # ==========================================================================
        # SYSTEM CONTEXT RELATIONSHIPS (External)
        # ==========================================================================

        endUser -> credo "Authenticates, manages consent, receives VCs" "HTTPS"
        oauthClient -> credo "OAuth 2.0 authorization, API calls" "HTTPS"
        adminOperator -> credo "Manages tenants, clients, monitors system" "HTTPS (Port 8081)"
        credo -> citizenRegistry "Verifies citizen identity" "HTTPS"
        credo -> sanctionsRegistry "Screens for PEP/sanctions" "HTTPS"
        credo -> observability "Exports metrics and traces" "Prometheus, OpenTelemetry"

        # ==========================================================================
        # COMPONENT RELATIONSHIPS (Level 4 - Code Level)
        # ==========================================================================

        # Auth Module internal relationships
        authService -> authRateLimitPort "depends on"
        authService -> authClientResolver "depends on"
        authService -> authAuditPublisher "emits events"
        rateLimitAdapter -> authRateLimitPort "implements"
        rateLimitAdapter -> ratelimitModule "calls"
        authService -> userStore "persists users"
        authService -> sessionStore "persists sessions"
        authService -> authCodeStore "persists auth codes"
        authService -> refreshTokenStore "persists tokens"
        authService -> revocationStore "tracks revoked JTIs"

        # Registry Module internal relationships
        registryService -> registryConsentPort "depends on"
        registryConsentAdapter -> registryConsentPort "implements"
        registryConsentAdapter -> consentModule "calls"
        citizenProvider -> citizenRegistry "HTTP"
        sanctionsProvider -> sanctionsRegistry "HTTP"
        registryService -> citizenRecord "returns"
        registryService -> sanctionsRecord "returns"

        # VC Module internal relationships
        vcService -> vcConsentPort "depends on"
        vcService -> vcRegistryPort "depends on"
        vcConsentAdapter -> vcConsentPort "implements"
        vcRegistryAdapter -> vcRegistryPort "implements"
        vcConsentAdapter -> consentModule "calls"
        vcRegistryAdapter -> registryModule "calls"
        vcService -> credentialRecord "issues"

        # Decision Module internal relationships
        decisionService -> decisionConsentPort "depends on"
        decisionService -> decisionRegistryPort "depends on"
        decisionService -> decisionVCPort "depends on"
        decisionConsentAdapter -> decisionConsentPort "implements"
        decisionRegistryAdapter -> decisionRegistryPort "implements"
        decisionVCAdapter -> decisionVCPort "implements"
        decisionConsentAdapter -> consentModule "calls"
        decisionRegistryAdapter -> registryModule "calls"
        decisionVCAdapter -> vcModule "calls"
        decisionService -> decisionResult "produces"

        # Rate Limit Module internal relationships
        requestLimitService -> bucketStorePort "depends on"
        authLockoutService -> authLockoutStorePort "depends on"
        globalThrottleService -> globalThrottleStorePort "depends on"
        clientLimitService -> clientLookupPort "depends on"
        bucketStore -> bucketStorePort "implements"
        allowlistStore -> allowlistStorePort "implements"
        authLockoutStore -> authLockoutStorePort "implements"
        globalThrottleStore -> globalThrottleStorePort "implements"

        # Tenant Module internal relationships
        tenantService -> tenantStorePort "depends on"
        tenantService -> clientStorePort "depends on"
        tenantService -> userCounterPort "depends on"
        tenantStore -> tenantStorePort "implements"
        clientStore -> clientStorePort "implements"

        # Admin Module internal relationships
        adminService -> adminUserStore "reads from"
        adminService -> adminSessionStore "reads from"

        # Platform Module internal relationships
        auditPublisher -> auditPublisherPort "implements"
        auditPublisher -> auditStore "persists"
        auditPublisher -> auditEvent "emits"
    }

    views {
        # ==========================================================================
        # LEVEL 1: SYSTEM CONTEXT
        # ==========================================================================

        systemContext credo "SystemContext" {
            include *
            autoLayout
            title "Credo - System Context (Level 1)"
            description "High-level view showing Credo and its external actors and systems"
        }

        # ==========================================================================
        # LEVEL 2: CONTAINER VIEWS
        # ==========================================================================

        container credo "Containers" {
            include *
            autoLayout
            title "Credo - Container View (Level 2)"
            description "All modules (containers) and their relationships"
        }

        # ==========================================================================
        # LEVEL 3: COMPONENT VIEWS
        # ==========================================================================

        component publicAPI "Components_PublicAPI" {
            include *
            autoLayout
            title "Public API Server - Components (Level 3)"
            description "Middleware stack for the public API server"
        }

        component adminAPI "Components_AdminAPI" {
            include *
            autoLayout
            title "Admin API Server - Components (Level 3)"
            description "Middleware stack for the admin API server"
        }

        component authModule "Components_Auth" {
            include *
            autoLayout
            title "Auth Module - Components (Level 3)"
            description "OAuth 2.0 authorization server components"
        }

        component consentModule "Components_Consent" {
            include *
            autoLayout
            title "Consent Module - Components (Level 3)"
            description "Purpose-based consent lifecycle components"
        }

        component registryModule "Components_Registry" {
            include *
            autoLayout
            title "Registry Module - Components (Level 3)"
            description "Multi-provider registry lookup components"
        }

        component vcModule "Components_VC" {
            include *
            autoLayout
            title "VC Module - Components (Level 3)"
            description "Verifiable credential issuance components"
        }

        component decisionModule "Components_Decision" {
            include *
            autoLayout
            title "Decision Module - Components (Level 3)"
            description "Rules engine components"
        }

        component ratelimitModule "Components_RateLimit" {
            include *
            autoLayout
            title "Rate Limit Module - Components (Level 3)"
            description "Rate limiting and DDoS protection components"
        }

        component tenantModule "Components_Tenant" {
            include *
            autoLayout
            title "Tenant Module - Components (Level 3)"
            description "Multi-tenancy and OAuth client management components"
        }

        component adminModule "Components_Admin" {
            include *
            autoLayout
            title "Admin Module - Components (Level 3)"
            description "Administrative query components"
        }

        component platformModule "Components_Platform" {
            include *
            autoLayout
            title "Platform Module - Components (Level 3)"
            description "Cross-cutting infrastructure components"
        }

        # ==========================================================================
        # LEVEL 4: CODE VIEWS (Ports & Adapters with Key Methods)
        # ==========================================================================

        # Auth Module - Hexagonal Boundaries
        component authModule "Code_Auth_Ports" {
            include authService
            include authRateLimitPort authClientResolver authAuditPublisher
            include rateLimitAdapter
            include userStore sessionStore authCodeStore refreshTokenStore revocationStore
            include ratelimitModule
            autoLayout lr
            title "Auth Module - Ports & Adapters (Level 4)"
            description "Hexagonal architecture: Service depends on port interfaces, adapters implement them"
        }

        # Registry Module - Hexagonal Boundaries
        component registryModule "Code_Registry_Ports" {
            include registryService orchestrator
            include registryConsentPort
            include registryConsentAdapter
            include citizenProvider sanctionsProvider
            include citizenRecord sanctionsRecord
            include consentModule
            include citizenRegistry sanctionsRegistry
            autoLayout lr
            title "Registry Module - Ports & Adapters (Level 4)"
            description "External registry adapters and consent port for cross-module calls"
        }

        # VC Module - Hexagonal Boundaries
        component vcModule "Code_VC_Ports" {
            include vcService
            include vcConsentPort vcRegistryPort
            include vcConsentAdapter vcRegistryAdapter
            include credentialRecord
            include consentModule registryModule
            autoLayout lr
            title "VC Module - Ports & Adapters (Level 4)"
            description "Dual-port architecture: consent and registry dependencies"
        }

        # Decision Module - Hexagonal Boundaries
        component decisionModule "Code_Decision_Ports" {
            include decisionService
            include decisionConsentPort decisionRegistryPort decisionVCPort
            include decisionConsentAdapter decisionRegistryAdapter decisionVCAdapter
            include decisionResult
            include consentModule registryModule vcModule
            autoLayout lr
            title "Decision Module - Ports & Adapters (Level 4)"
            description "Rules engine with three port dependencies for evidence evaluation"
        }

        # Rate Limit Module - Store Ports
        component ratelimitModule "Code_RateLimit_Ports" {
            include limiter requestLimitService authLockoutService globalThrottleService clientLimitService
            include bucketStorePort allowlistStorePort authLockoutStorePort globalThrottleStorePort clientLookupPort
            include bucketStore allowlistStore authLockoutStore globalThrottleStore
            include rateLimitResult authLockout
            autoLayout lr
            title "Rate Limit Module - Store Ports (Level 4)"
            description "Five store interfaces with atomic operations for thread-safe rate limiting"
        }

        # Tenant Module - Store Ports
        component tenantModule "Code_Tenant_Ports" {
            include tenantService
            include tenantStorePort clientStorePort userCounterPort
            include tenantStore clientStore
            include tenantAggregate clientAggregate
            autoLayout lr
            title "Tenant Module - Store Ports (Level 4)"
            description "Store interfaces for tenant and OAuth client persistence"
        }

        # Platform Module - Audit Subsystem
        component platformModule "Code_Platform_Audit" {
            include auditPublisherPort
            include auditPublisher auditStore
            include auditEvent
            autoLayout lr
            title "Platform Module - Audit Ports (Level 4)"
            description "Tri-publisher audit system with sync/async/metrics emission"
        }

        # ==========================================================================
        # MODERN STYLING (Contemporary Design System)
        # ==========================================================================

        styles {
            # Persons - Warm, approachable
            element "Person" {
                shape Person
                background #4F46E5
                color #ffffff
                fontSize 16
            }

            # Software Systems - Primary brand color
            element "Software System" {
                background #6366F1
                color #ffffff
                fontSize 18
            }

            # External Systems - Muted, clearly external
            element "External System" {
                background #64748B
                color #ffffff
                fontSize 14
            }

            # Containers - Secondary accent
            element "Container" {
                background #8B5CF6
                color #ffffff
                fontSize 14
            }

            # Components - Light, readable
            element "Component" {
                background #E0E7FF
                color #1E1B4B
                fontSize 12
            }

            # API Gateways - Success/Active color
            element "API Gateway" {
                shape WebBrowser
                background #059669
                color #ffffff
                fontSize 14
            }

            # Domain Modules - Distinctive hexagon
            element "Domain Module" {
                shape Hexagon
                background #7C3AED
                color #ffffff
                fontSize 14
            }

            # Infrastructure - Neutral
            element "Infrastructure" {
                shape Folder
                background #475569
                color #ffffff
                fontSize 12
            }

            # Handlers - Coral/Salmon
            element "Handler" {
                shape RoundedBox
                background #FB7185
                color #1E1B4B
                fontSize 12
            }

            # Services - Sky blue
            element "Service" {
                shape RoundedBox
                background #38BDF8
                color #0C4A6E
                fontSize 12
            }

            # Stores - Cylinder, muted purple
            element "Store" {
                shape Cylinder
                background #C4B5FD
                color #3730A3
                fontSize 12
            }

            # Adapters - Mint green
            element "Adapter" {
                shape RoundedBox
                background #34D399
                color #064E3B
                fontSize 12
            }

            # Middleware - Amber/Yellow
            element "Middleware" {
                shape Pipe
                background #FCD34D
                color #78350F
                fontSize 12
            }

            # Workers - Orange
            element "Worker" {
                shape Robot
                background #FB923C
                color #7C2D12
                fontSize 12
            }

            # Ports (Interfaces) - Distinctive border style
            element "Port" {
                shape RoundedBox
                background #FEF3C7
                color #92400E
                border dashed
                fontSize 11
            }

            # Domain Aggregates - Entity style
            element "Aggregate" {
                shape RoundedBox
                background #DBEAFE
                color #1E3A8A
                border solid
                fontSize 11
            }

            # Relationships - Clean, modern lines
            relationship "Relationship" {
                thickness 2
                color #6B7280
                style solid
            }

            relationship "HTTPS" {
                thickness 2
                color #9CA3AF
                style dashed
            }

            relationship "implements" {
                thickness 2
                color #10B981
                style solid
            }

            relationship "depends on" {
                thickness 2
                color #8B5CF6
                style dashed
            }

            relationship "calls" {
                thickness 2
                color #3B82F6
                style solid
            }
        }

        # ==========================================================================
        # THEME & BRANDING
        # ==========================================================================

        theme default
    }
}
