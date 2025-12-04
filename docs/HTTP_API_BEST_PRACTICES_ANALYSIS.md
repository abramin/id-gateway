# HTTP API Setup Analysis: Best Practices Review

**Date:** 2025-12-03
**Status:** Current implementation has some good practices but missing several critical ones

---

## Current State: What's Good ✅

### 1. **Graceful Shutdown** ✅
**Location:** `cmd/server/main.go:36-45`

```go
quit := make(chan os.Signal, 1)
signal.Notify(quit, os.Interrupt)
<-quit

ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    log.Fatalf("graceful shutdown failed: %v", err)
}
```

**Good:**
- Handles SIGINT (Ctrl+C)
- 10-second timeout for shutdown
- Allows in-flight requests to complete

**Missing:**
- No SIGTERM handling (needed for container orchestration)
- No cleanup of background workers (audit worker, etc.)

---

### 2. **ReadHeaderTimeout** ✅
**Location:** `internal/platform/httpserver/httpserver.go:13`

```go
ReadHeaderTimeout: 5 * time.Second,
```

**Good:**
- Prevents Slowloris attacks
- 5 seconds is reasonable for headers

**Missing:**
- No `ReadTimeout` (body reading can take forever)
- No `WriteTimeout` (response writing can hang)
- No `IdleTimeout` (keep-alive connections never close)

---

### 3. **Method Validation** ✅
**Location:** `internal/transport/http/router.go:41-49`

```go
func method(method string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != method {
            w.WriteHeader(http.StatusMethodNotAllowed)
            return
        }
        next(w, r)
    }
}
```

**Good:**
- Enforces HTTP verb per endpoint
- Returns 405 Method Not Allowed

**Missing:**
- No `Allow` header in response (should list allowed methods)
- Could use `http.HandlerFunc` wrapping more elegantly

---

### 4. **Centralized Error Handling** ✅
**Location:** `internal/transport/http/router.go:62-75`

```go
func writeError(w http.ResponseWriter, err error) {
    // Maps domain errors to HTTP status codes
    // Consistent JSON format
}
```

**Good:**
- Typed error codes (from `pkg/errors`)
- Consistent JSON error format
- Proper status code mapping

**Missing:**
- No error logging
- No correlation ID in error response
- No request ID for tracing

---

## Critical Missing Best Practices ❌

### 1. **Request/Write/Idle Timeouts** ❌

**Current:**
```go
ReadHeaderTimeout: 5 * time.Second,
```

**Should be:**
```go
ReadHeaderTimeout: 5 * time.Second,   // Headers only
ReadTimeout:       10 * time.Second,  // Full request (headers + body)
WriteTimeout:      10 * time.Second,  // Full response
IdleTimeout:       120 * time.Second, // Keep-alive timeout
```

**Why it matters:**
- **ReadTimeout**: Prevents slow clients from tying up connections
- **WriteTimeout**: Prevents slow clients from blocking response writes
- **IdleTimeout**: Prevents zombie connections from consuming resources

**Impact of missing:**
- Clients can hold connections open indefinitely
- Slow POST requests can exhaust server resources
- No protection against slowloris-style attacks

---

### 2. **CORS Headers** ❌

**Currently:** No CORS support at all

**Needed for:**
- Web UI accessing the API
- Cross-origin requests from demo apps
- Browser-based testing

**Should add middleware:**
```go
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*") // or specific origins
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusNoContent)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

---

### 3. **Request ID / Correlation ID** ❌

**Currently:** No request tracking

**Should add:**
```go
func requestIDMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestID := r.Header.Get("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
        }

        // Add to context for logging
        ctx := context.WithValue(r.Context(), "request_id", requestID)

        // Add to response headers
        w.Header().Set("X-Request-ID", requestID)

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Benefits:**
- Trace requests across services
- Debug specific requests
- Correlate logs and audit events

---

### 4. **Request Logging Middleware** ❌

**Currently:** No automatic request logging

**Should add:**
```go
func loggingMiddleware(log *log.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()

            // Wrap response writer to capture status code
            wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

            next.ServeHTTP(wrapped, r)

            duration := time.Since(start)
            log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, duration)
        })
    }
}

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}
```

---

### 5. **Panic Recovery Middleware** ❌

**Currently:** Panics crash the entire server

**Should add:**
```go
func recoveryMiddleware(log *log.Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            defer func() {
                if err := recover(); err != nil {
                    log.Printf("panic recovered: %v\n%s", err, debug.Stack())
                    w.WriteHeader(http.StatusInternalServerError)
                    json.NewEncoder(w).Encode(map[string]string{
                        "error": "internal_server_error",
                    })
                }
            }()
            next.ServeHTTP(w, r)
        })
    }
}
```

**Why critical:**
- Prevents one bad request from crashing the server
- Logs stack trace for debugging
- Returns 500 to client instead of connection reset

---

### 6. **Content-Type Validation** ❌

**Currently:** Handlers accept any content type

**Should validate:**
```go
func requireJSON(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" || r.Method == "PUT" {
            ct := r.Header.Get("Content-Type")
            if ct != "application/json" && !strings.HasPrefix(ct, "application/json;") {
                w.WriteHeader(http.StatusUnsupportedMediaType)
                json.NewEncoder(w).Encode(map[string]string{
                    "error": "content_type_must_be_application_json",
                })
                return
            }
        }
        next(w, r)
    }
}
```

---

### 7. **Request Size Limits** ❌

**Currently:** No limit on request body size

**Should add:**
```go
func limitRequestBody(maxBytes int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
            next.ServeHTTP(w, r)
        })
    }
}

// Usage: limit to 1MB
router = limitRequestBody(1 << 20)(router)
```

**Why it matters:**
- Prevents large payload DoS attacks
- Protects memory usage
- Fails fast instead of OOM

---

### 8. **Security Headers** ❌

**Currently:** No security headers

**Should add:**
```go
func securityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        next.ServeHTTP(w, r)
    })
}
```

---

### 9. **Health Check Endpoint** ❌

**Currently:** No health check

**Should add:**
```go
mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "status": "healthy",
        "version": "1.0.0",
    })
})

// Optional: readiness check (includes DB, queue, etc.)
mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
    // Check dependencies
    if err := checkDatabase(); err != nil {
        w.WriteHeader(http.StatusServiceUnavailable)
        return
    }
    w.WriteHeader(http.StatusOK)
})
```

**Used by:**
- Kubernetes liveness/readiness probes
- Load balancers
- Monitoring systems

---

### 10. **Context Propagation** ❌

**Currently:** Context passed but not enriched

**Should add to context:**
- Request ID
- User ID (after auth)
- Correlation ID
- Timeout/deadline

**Example:**
```go
type contextKey string

const (
    requestIDKey contextKey = "request_id"
    userIDKey    contextKey = "user_id"
)

// In middleware:
ctx := context.WithValue(r.Context(), requestIDKey, requestID)

// In handlers:
requestID := r.Context().Value(requestIDKey).(string)
```

---

## Recommended Middleware Stack (Priority Order)

### P0 - Critical (Add First)

1. **Panic Recovery** - Prevents crashes
2. **Request ID** - Essential for debugging
3. **Request Logging** - Operational visibility
4. **Timeouts (Read/Write/Idle)** - Resource protection

### P1 - High Priority

5. **CORS** - Needed if you add a web UI
6. **Request Size Limits** - DoS protection
7. **Content-Type Validation** - Input validation

### P2 - Should Have

8. **Security Headers** - Defense in depth
9. **Health Checks** - Deployment requirements
10. **Context Propagation** - Better logging/tracing

---

## Proposed Middleware Chain

**Order matters!** Apply in this sequence:

```go
func NewRouter(h *Handler, log *log.Logger) http.Handler {
    mux := http.NewServeMux()

    // Route definitions
    mux.HandleFunc("/auth/authorize", method(http.MethodPost, h.handleAuthorize))
    // ... other routes

    // Add health check
    mux.HandleFunc("/health", healthCheck)

    // Build middleware chain (innermost to outermost)
    var handler http.Handler = mux

    handler = limitRequestBody(1 << 20)(handler)           // 1MB limit
    handler = requireJSON(handler)                          // JSON validation
    handler = securityHeadersMiddleware(handler)            // Security headers
    handler = corsMiddleware(handler)                       // CORS
    handler = loggingMiddleware(log)(handler)              // Request logging
    handler = requestIDMiddleware(handler)                  // Request ID
    handler = recoveryMiddleware(log)(handler)             // Panic recovery

    return handler
}
```

**Execution order (request flows top to bottom):**
1. Panic recovery catches any panics
2. Request ID added to context
3. Request logged
4. CORS headers set
5. Security headers set
6. JSON content-type validated
7. Request body size limited
8. Actual handler executes

---

## Quick Wins (30 Minutes)

### Add These Now to router.go:

```go
// At the top
import (
    "context"
    "runtime/debug"
    "github.com/google/uuid"
)

// Add after method() function
func recoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                log.Printf("panic: %v\n%s", err, debug.Stack())
                w.WriteHeader(500)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

func requestIDMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        id := r.Header.Get("X-Request-ID")
        if id == "" {
            id = uuid.New().String()
        }
        w.Header().Set("X-Request-ID", id)
        ctx := context.WithValue(r.Context(), "request_id", id)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Update NewRouter to wrap mux
func NewRouter(h *Handler) http.Handler {
    mux := http.NewServeMux()
    // ... routes

    var handler http.Handler = mux
    handler = requestIDMiddleware(handler)
    handler = recoveryMiddleware(handler)
    return handler
}
```

---

### Update httpserver.go:

```go
func New(addr string, handler http.Handler) *http.Server {
    return &http.Server{
        Addr:              addr,
        Handler:           handler,
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       10 * time.Second,  // ADD
        WriteTimeout:      10 * time.Second,  // ADD
        IdleTimeout:       120 * time.Second, // ADD
    }
}
```

---

## Summary

### Currently Has (4/10)
✅ Graceful shutdown (partial - missing SIGTERM)
✅ ReadHeaderTimeout
✅ Method validation
✅ Centralized error handling

### Critical Missing (6/10)
❌ Full timeout suite (Read/Write/Idle)
❌ Request ID / correlation
❌ Request logging
❌ Panic recovery
❌ CORS headers
❌ Request size limits

### Should Add (but not blocking)
- Security headers
- Content-type validation
- Health check endpoints
- Context propagation

---

## Impact Assessment

**Without these changes:**
- ⚠️ Server can be DoS'd with slow requests
- ⚠️ Panics crash the entire service
- ⚠️ No way to trace individual requests
- ⚠️ No operational visibility (logs)
- ⚠️ Cannot use with web UI (CORS)
- ⚠️ Not Kubernetes-ready (no health checks)

**Interview implications:**
- Shows lack of production API experience
- Missing standard middleware patterns
- No awareness of common vulnerabilities

**With these changes:**
- ✅ Production-ready HTTP server
- ✅ Demonstrates security awareness
- ✅ Shows operational maturity
- ✅ Interview-ready talking points

---

## Recommendation

**Phase 1 (1 hour):** Add panic recovery, request ID, full timeouts
**Phase 2 (1 hour):** Add logging middleware, CORS, health checks
**Phase 3 (30 min):** Add security headers, content-type validation

**Total: 2.5 hours to go from "basic" to "production-ready" HTTP setup**

This should be done **before** implementing handlers, as it affects all endpoints.
