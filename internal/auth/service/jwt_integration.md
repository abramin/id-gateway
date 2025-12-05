# JWT Integration TODO

## Steps to integrate JWT into the auth service:

### 1. Update Service struct (in service.go)
Add a JWT service field:
```go
type Service struct {
    users          UserStore
    sessions       SessionStore
    sessionTTL     time.Duration
    jwtService     *jwttoken.JWTService  // TODO: Add this field
    logger         *slog.Logger
    auditPublisher AuditPublisher
    metrics        *metrics.Metrics
}
```

### 2. Add WithJWTService option (in service.go)
```go
func WithJWTService(jwtService *jwttoken.JWTService) Option {
    return func(s *Service) {
        s.jwtService = jwtService
    }
}
```

### 3. Update Token() method (in service.go)
Find the Token method and replace the fake token generation with real JWT:

Current (fake):
```go
accessToken := "at_sess_" + session.ID.String()
idToken := "id_sess_" + session.ID.String()
```

TODO: Replace with:
```go
// Generate real JWT access token
accessToken, err := s.jwtService.GenerateAccessToken(
    session.UserID,
    session.ID,
    req.ClientID,
    s.sessionTTL,
)
if err != nil {
    // Handle error
}

// For now, keep ID token as-is or generate separately
idToken := "id_sess_" + session.ID.String()
```

### 4. Update main.go to wire everything together
You'll need to:
- Create JWTService instance with signing key from env/config
- Pass it to the auth service via WithJWTService option
- Create JWTServiceAdapter
- Add RequireAuth middleware to protected routes (like consent endpoints)

Example:
```go
// Create JWT service
jwtService := jwttoken.NewJWTService(
    os.Getenv("JWT_SIGNING_KEY"), // TODO: Set this env var
    "id-gateway",                  // issuer
    "id-gateway-clients",          // audience
)

// Create auth service with JWT
authService := service.NewService(
    userStore,
    sessionStore,
    sessionTTL,
    service.WithJWTService(jwtService),
    // ... other options
)

// Create adapter for middleware
jwtValidator := jwttoken.NewJWTServiceAdapter(jwtService)

// Apply to protected routes
consentRouter.Use(middleware.RequireAuth(jwtValidator, logger))
```

## Testing your implementation

1. Complete all the TODO functions in jwt.go
2. Complete all the TODO functions in auth.go (middleware)
3. Complete the adapter in jwt_adapter.go
4. Update service.go to use JWT in Token() method
5. Update main.go to wire it together
6. Run integration tests
7. Test with the demo client

Remember: The signing key should be a secret value (32+ bytes), stored in environment variables, not hardcoded!
