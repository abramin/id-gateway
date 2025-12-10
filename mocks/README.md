# Mock Registry Services

This directory contains mock external registry services that simulate real third-party APIs for testing and development.

## Services

### 1. Citizen Registry (`citizen-registry/`)

Simulates a national citizen/population registry API.

**Port:** 8081
**API Key:** `citizen-registry-secret-key`
**Endpoint:** `POST /api/v1/citizen/lookup`

**Features:**

- Deterministic data generation based on national ID hash
- Configurable network latency simulation (default: 100ms)
- API key authentication
- Realistic citizen data (name, DOB, address)
- 95% of records are valid by default

### 2. Sanctions Registry (`sanctions-registry/`)

Simulates an international sanctions/PEP screening API.

**Port:** 8082
**API Key:** `sanctions-registry-secret-key`
**Endpoint:** `POST /api/v1/sanctions/check`

**Features:**

- Deterministic sanctions status based on national ID hash
- Configurable network latency simulation (default: 50ms)
- API key authentication
- ~10% of IDs flagged as listed (sanctions/PEP/watchlist)
- Detailed listing information (type, reason, date)

## Running the Services

### With Docker Compose (Recommended)

```bash
# Start all services including mock registries
docker-compose up -d

# Check service health
curl http://localhost:8081/health
curl http://localhost:8082/health

# Stop services
docker-compose down
```

### Standalone Development

```bash
# Citizen Registry
cd mocks/citizen-registry
PORT=8081 API_KEY=test-key LATENCY_MS=100 go run main.go

# Sanctions Registry
cd mocks/sanctions-registry
PORT=8082 API_KEY=test-key LATENCY_MS=50 go run main.go
```

## Usage Examples

### Citizen Lookup

```bash
curl -X POST http://localhost:8081/api/v1/citizen/lookup \
  -H "Content-Type: application/json" \
  -H "X-API-Key: citizen-registry-secret-key" \
  -d '{"national_id": "123456789"}'
```

**Response:**

```json
{
  "national_id": "123456789",
  "full_name": "Alice Marie Johnson",
  "date_of_birth": "1990-05-15",
  "address": "123 Main Street, Springfield, IL 62701",
  "valid": true,
  "checked_at": "2025-12-10T10:00:00Z"
}
```

### Sanctions Check

```bash
curl -X POST http://localhost:8082/api/v1/sanctions/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sanctions-registry-secret-key" \
  -d '{"national_id": "123456789"}'
```

**Response (Not Listed):**

```json
{
  "national_id": "123456789",
  "listed": false,
  "source": "Mock International Sanctions Database",
  "checked_at": "2025-12-10T10:00:00Z"
}
```

**Response (Listed):**

```json
{
  "national_id": "987654321",
  "listed": true,
  "source": "Mock International Sanctions Database",
  "list_type": "pep",
  "reason": "Politically Exposed Person - Government Official",
  "listed_date": "2021-03-15",
  "checked_at": "2025-12-10T10:00:00Z"
}
```

## Configuration

Environment variables for each service:

| Variable     | Default     | Description                               |
| ------------ | ----------- | ----------------------------------------- |
| `PORT`       | 8081/8082   | Server port                               |
| `API_KEY`    | (see above) | Required API key for authentication       |
| `LATENCY_MS` | 100/50      | Simulated network latency in milliseconds |

## Error Responses

### 401 Unauthorized

```json
{
  "error": "Unauthorized",
  "message": "Missing X-API-Key header",
  "code": 401
}
```

### 400 Bad Request

```json
{
  "error": "Bad Request",
  "message": "national_id is required",
  "code": 400
}
```

### 405 Method Not Allowed

```json
{
  "error": "Method Not Allowed",
  "message": "Method not allowed",
  "code": 405
}
```

## Integration with Main Application

The main Credo backend is configured to use these mock registries via environment variables:

```bash
CITIZEN_REGISTRY_URL=http://citizen-registry:8081
CITIZEN_REGISTRY_API_KEY=citizen-registry-secret-key
SANCTIONS_REGISTRY_URL=http://sanctions-registry:8082
SANCTIONS_REGISTRY_API_KEY=sanctions-registry-secret-key
```

See [docker-compose.yml](../docker-compose.yml) for the full configuration.

## Deterministic Behavior

Both services use SHA-256 hashing of the national ID to generate deterministic but pseudo-random data:

- **Same ID** → Always returns the **same data**
- **Different IDs** → Return different data based on hash

This makes testing predictable and reproducible:

```bash
# These will always return the same person
curl ... -d '{"national_id": "ABC123"}'  # Always "Bob James Miller"
curl ... -d '{"national_id": "ABC123"}'  # Always "Bob James Miller"

# Different ID returns different person
curl ... -d '{"national_id": "XYZ789"}'  # Always "Grace Ann Davis"
```

## Production Considerations

⚠️ **These are mock services for development/testing only!**

For production:

1. Replace with real registry provider clients
2. Use secure credential management
3. Implement proper rate limiting
4. Add retry logic and circuit breakers
5. Enable comprehensive logging and monitoring
6. Consider caching strategies (already implemented in the main service)

## Architecture

```
┌─────────────────┐      ┌──────────────────────┐
│  Credo Backend  │─────▶│  Citizen Registry    │
│                 │      │  (Mock API :8081)    │
│                 │      └──────────────────────┘
│                 │
│                 │      ┌──────────────────────┐
│                 │─────▶│  Sanctions Registry  │
│                 │      │  (Mock API :8082)    │
└─────────────────┘      └──────────────────────┘
```

The backend uses HTTP clients that implement the `CitizenClient` and `SanctionsClient` interfaces, making it easy to swap between mock and real implementations.

## Testing

You can test the mock services independently:

```bash
# Build and test citizen registry
cd mocks/citizen-registry
go build
./citizen-registry &
curl http://localhost:8081/health

# Build and test sanctions registry
cd mocks/sanctions-registry
go build
./sanctions-registry &
curl http://localhost:8082/health
```

## See Also

- [PRD-003: Registry Integration](../docs/prd/PRD-003-Registry-Integration.md)
- [Integration Tests](../internal/evidence/registry/integration_test.go)
- [HTTP Client Implementation](../internal/evidence/registry/clients/)
