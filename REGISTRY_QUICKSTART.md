# Registry Integration Quick Start

Quick guide to get started with the mock registry services and test the registry integration.

## Start the Services

```bash
# Start all services (backend, frontend, and mock registries)
docker-compose up -d

# Check all services are healthy
docker-compose ps

# View logs
docker-compose logs -f citizen-registry
docker-compose logs -f sanctions-registry
```

## Test the Mock Registries Directly

### Test Citizen Registry

```bash
# Health check
curl http://localhost:8081/health

# Lookup a citizen (will always return "Alice Marie Johnson")
curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: citizen-registry-secret-key" \
  -d '{"national_id": "123456789"}' | jq

# Try different IDs to see deterministic behavior
curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: citizen-registry-secret-key" \
  -d '{"national_id": "ABC123"}' | jq
```

### Test Sanctions Registry

```bash
# Health check
curl http://localhost:8082/health

# Check sanctions (most IDs will return listed=false)
curl -X POST http://localhost:8082/api/v1/sanctions/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sanctions-registry-secret-key" \
  -d '{"national_id": "123456789"}' | jq

# Try an ID that will be listed (deterministic - ends with specific hex values)
curl -X POST http://localhost:8082/api/v1/sanctions/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sanctions-registry-secret-key" \
  -d '{"national_id": "SANCTIONED"}' | jq
```

## Test Error Scenarios

### Missing API Key

```bash
curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -d '{"national_id": "123456789"}'
# Expected: 401 Unauthorized
```

### Invalid API Key

```bash
curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: wrong-key" \
  -d '{"national_id": "123456789"}'
# Expected: 401 Unauthorized
```

### Missing national_id

```bash
curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: citizen-registry-secret-key" \
  -d '{}'
# Expected: 400 Bad Request
```

### Wrong HTTP Method

```bash
curl -X GET http://localhost:8081/api/v1/citizen/lookup \
  -H "X-API-Key: citizen-registry-secret-key"
# Expected: 405 Method Not Allowed
```

## Test Through Main Backend (End-to-End)

Once the handlers are implemented, you can test the full flow:

```bash
# 1. Get authentication token (assuming auth is set up)
TOKEN=$(curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password"}' | jq -r '.token')

# 2. Grant consent for registry checks
curl -X POST http://localhost:8080/auth/consent \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"purposes":["registry_check"]}'

# 3. Perform citizen lookup
curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id":"123456789"}' | jq

# 4. Perform sanctions check
curl -X POST http://localhost:8080/registry/sanctions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id":"123456789"}' | jq

# 5. Second call should be faster (cache hit)
time curl -X POST http://localhost:8080/registry/citizen \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"national_id":"123456789"}' | jq
```

## Observe Cache Behavior

```bash
# First call - cache miss (~100ms latency)
time curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: citizen-registry-secret-key" \
  -d '{"national_id":"TEST123"}' | jq

# Second call - cache hit (should be <5ms when going through backend)
time curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: citizen-registry-secret-key" \
  -d '{"national_id":"TEST123"}' | jq
```

## Run Integration Tests

```bash
# Run all registry tests
go test ./internal/evidence/registry/... -v

# Run integration tests only
go test ./internal/evidence/registry -run TestRegistryIntegrationSuite -v

# Run with race detection
go test ./internal/evidence/registry/... -race -v
```

## Environment Variables

### Backend Configuration

```bash
# In .env or docker-compose.yml
CITIZEN_REGISTRY_URL=http://citizen-registry:8081
CITIZEN_REGISTRY_API_KEY=citizen-registry-secret-key
SANCTIONS_REGISTRY_URL=http://sanctions-registry:8082
SANCTIONS_REGISTRY_API_KEY=sanctions-registry-secret-key
REGULATED_MODE=true  # Enable data minimization
```

### Mock Service Configuration

```bash
# Citizen Registry
PORT=8081
API_KEY=citizen-registry-secret-key
LATENCY_MS=100  # Simulate 100ms network latency

# Sanctions Registry
PORT=8082
API_KEY=sanctions-registry-secret-key
LATENCY_MS=50   # Simulate 50ms network latency
```

## Troubleshooting

### Services not starting

```bash
# Check logs
docker-compose logs citizen-registry
docker-compose logs sanctions-registry

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d
```

### Connection refused

```bash
# Ensure services are running
docker-compose ps

# Check network
docker network inspect id-gateway_credo-network

# Try direct connection
docker exec -it credo-backend wget -O- http://citizen-registry:8081/health
```

### Port conflicts

```bash
# Check what's using the ports
lsof -i :8081
lsof -i :8082

# Change ports in docker-compose.yml if needed
```

## See Also

- [PRD-003: Registry Integration](docs/prd/PRD-003-Registry-Integration.md)
- [Mock Services README](mocks/README.md)
- [Architecture Documentation](docs/architecture.md)
