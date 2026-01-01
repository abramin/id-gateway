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
                rateLimitAdapter = component "Rate Limit Adapter" "Adapter implementing RateLimitPort" "Go" "Adapter"
            }

            # ----------------------------------------------------------------------
            # CONSENT MODULE
            # ----------------------------------------------------------------------

            consentModule = container "Consent Module" "Purpose-based consent lifecycle management" "Go" "Domain Module" {
                consentHandler = component "Consent Handler" "HTTP handlers for consent endpoints" "Go" "Handler"
                consentService = component "Consent Service" "Grant, require, revoke consent with idempotency windows" "Go" "Service"
                consentStore = component "Consent Store" "Consent record persistence" "In-Memory" "Store"
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
                registryConsentAdapter = component "Consent Adapter" "Adapter implementing ConsentPort" "Go" "Adapter"
            }

            # ----------------------------------------------------------------------
            # VC MODULE (Evidence/VC)
            # ----------------------------------------------------------------------

            vcModule = container "VC Module" "Verifiable Credential issuance for age verification" "Go" "Domain Module" {
                vcHandler = component "VC Handler" "HTTP handler for /credentials endpoint" "Go" "Handler"
                vcService = component "VC Service" "Issues age-over-18 credentials after verification" "Go" "Service"
                vcStore = component "VC Store" "Credential record persistence" "In-Memory" "Store"
                vcConsentAdapter = component "Consent Adapter" "Adapter implementing ConsentPort for VC" "Go" "Adapter"
                vcRegistryAdapter = component "Registry Adapter" "Adapter implementing RegistryPort for VC" "Go" "Adapter"
            }

            # ----------------------------------------------------------------------
            # DECISION MODULE
            # ----------------------------------------------------------------------

            decisionModule = container "Decision Module" "Rules engine combining evidence and consent" "Go" "Domain Module" {
                decisionService = component "Decision Service" "Evaluates pass/fail/conditions based on derived identity" "Go" "Service"
                decisionRegistryAdapter = component "Registry Adapter" "Adapter implementing RegistryPort for decision" "Go" "Adapter"
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
                bucketStore = component "Bucket Store" "Sliding window counter persistence" "In-Memory" "Store"
                allowlistStore = component "Allowlist Store" "Rate limit bypass entries" "In-Memory" "Store"
                authLockoutStore = component "Auth Lockout Store" "Authentication failure tracking" "In-Memory" "Store"
                globalThrottleStore = component "Global Throttle Store" "Global request counter" "In-Memory" "Store"
            }

            # ----------------------------------------------------------------------
            # TENANT MODULE
            # ----------------------------------------------------------------------

            tenantModule = container "Tenant Module" "Multi-tenancy and OAuth 2.0 client management" "Go" "Domain Module" {
                tenantHandler = component "Tenant Handler" "HTTP handlers for /tenants and /clients endpoints" "Go" "Handler"
                tenantService = component "Tenant Service" "Tenant and client CRUD, client type resolution" "Go" "Service"
                tenantStore = component "Tenant Store" "Tenant record persistence" "In-Memory" "Store"
                clientStore = component "Client Store" "OAuth client record persistence" "In-Memory" "Store"
            }

            # ----------------------------------------------------------------------
            # ADMIN MODULE
            # ----------------------------------------------------------------------

            adminModule = container "Admin Module" "Administrative queries and statistics" "Go" "Domain Module" {
                adminHandler = component "Admin Handler" "HTTP handlers for /admin/* endpoints" "Go" "Handler"
                adminService = component "Admin Service" "Read-only admin queries (stats, user info, sessions)" "Go" "Service"
            }

            # ----------------------------------------------------------------------
            # PLATFORM MODULE (Cross-cutting)
            # ----------------------------------------------------------------------

            platformModule = container "Platform Module" "Cross-cutting infrastructure concerns" "Go" "Infrastructure" {
                configLoader = component "Config Loader" "Environment-based configuration loading" "Go" "Infrastructure"
                logger = component "Logger" "Structured slog-based logging" "Go" "Infrastructure"
                jwtService = component "JWT Service" "Token signing and validation" "Go, HMAC-SHA256" "Service"
                auditPublisher = component "Audit Publisher" "Async event publishing with buffering" "Go" "Service"
                auditStore = component "Audit Store" "Audit event persistence" "In-Memory" "Store"
                metricsRegistry = component "Metrics Registry" "Prometheus metrics collection" "Go, Prometheus" "Infrastructure"
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
        # STYLING
        # ==========================================================================

        styles {
            element "Person" {
                shape Person
                background #08427B
                color #ffffff
            }
            element "Software System" {
                background #1168BD
                color #ffffff
            }
            element "External System" {
                background #999999
                color #ffffff
            }
            element "Container" {
                background #438DD5
                color #ffffff
            }
            element "Component" {
                background #85BBF0
                color #000000
            }
            element "API Gateway" {
                shape WebBrowser
                background #2E7D32
                color #ffffff
            }
            element "Domain Module" {
                shape Hexagon
                background #1565C0
                color #ffffff
            }
            element "Infrastructure" {
                shape Folder
                background #6A1B9A
                color #ffffff
            }
            element "Handler" {
                shape Component
                background #FFA07A
                color #000000
            }
            element "Service" {
                shape Component
                background #87CEEB
                color #000000
            }
            element "Store" {
                shape Cylinder
                background #DDA0DD
                color #000000
            }
            element "Adapter" {
                shape Component
                background #90EE90
                color #000000
            }
            element "Middleware" {
                shape Pipe
                background #F0E68C
                color #000000
            }
            element "Worker" {
                shape Robot
                background #FFB74D
                color #000000
            }
            relationship "Relationship" {
                dashed false
            }
            relationship "HTTPS" {
                color #999999
                style dashed
            }
        }
    }
}
