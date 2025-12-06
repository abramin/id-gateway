# Credo - Quick Start Guide

Get up and running with Credo demo in 5 minutes.

## Prerequisites

- Docker and Docker Compose
- OR: Go 1.21+ and a web server (Python, Node.js, etc.)

## Method 1: Docker (Easiest)

### Start Everything

```bash
docker-compose up --build
```

This starts:

- **Backend API** on port 8080
- **Frontend UI** on port 3000

### Access the Demo

Open your browser:

- User Portal: http://localhost:3000
- Admin Dashboard: http://localhost:3000/admin.html
- API directly: http://localhost:8080

### Stop Everything

```bash
docker-compose down
```

## Method 2: Local Development

### Start Backend

Terminal 1:

```bash
go run ./cmd/server
```

Backend runs on http://localhost:8080

### Start Frontend

Terminal 2:

```bash
cd frontend/public
python3 -m http.server 8000
```

Frontend runs on http://localhost:8000

## Demo Walkthrough

### User Flow

1. **Login** (http://localhost:3000)

   - Enter any email (e.g., `demo@example.com`)
   - Click "Sign In"
   - User is auto-created

2. **Grant Consent**

   - Click "Grant" on each consent card:
     - Registry Check
     - VC Issuance
     - Decision Evaluation

3. **Identity Verification**

   - Enter a National ID (e.g., `123456789`)
   - Click "Check Citizen Registry"
   - Click "Check Sanctions"
   - See the results

4. **Issue Credential**

   - Click "Issue Age Over 18 Credential"
   - See VC details

5. **Evaluate Decision**

   - Select purpose (Age Verification)
   - Click "Evaluate Decision"
   - See pass/fail result

6. **Data Rights**
   - Click "Export My Data" to download JSON
   - Click "Delete My Account" to test GDPR deletion

### Admin Dashboard

1. **Open Admin View** (http://localhost:3000/admin.html)

2. **See Live Stats**

   - Total users
   - Active sessions
   - VCs issued
   - Decisions made

3. **Recent Decisions**

   - Color-coded outcomes
   - Reasons and conditions

4. **Regulated Mode Comparison**

   - Side-by-side data view
   - See PII stripping in action

5. **Live Audit Stream**
   - Real-time events
   - Filter by action type

## Key Features to Demo

### 1. Privacy by Design

Toggle regulated mode and see how PII is stripped while decisions still work:

- Standard Mode: Full name, DOB, address visible
- Regulated Mode: Only "IsOver18: true" (derived attribute)

### 2. Consent Enforcement

Try to:

1. Issue VC without granting consent → See 403 error
2. Grant consent → Same operation succeeds

### 3. Decision Engine

Test different scenarios:

- Sanctioned user → Fail
- Under 18 → Fail
- Valid with VC → Pass
- Valid without VC → Pass with Conditions

### 4. GDPR Compliance

Export data:

- See all audit events
- See all consents
- See all credentials

Delete account:

- All PII removed
- Audit logs retained but pseudonymized

## Environment Variables

Backend (optional):

```bash
export ADDR=:8080
export REGULATED_MODE=true
export LOG_LEVEL=info
```

Frontend (automatic):

- Detects environment and configures API calls
- No manual configuration needed

## Troubleshooting

### Backend won't start

```bash
# Check if port 8080 is in use
lsof -i :8080

# Check Go version
go version  # Should be 1.21+

# Rebuild
go mod download
go build ./cmd/server
```

### Frontend can't reach backend

Check API base URL in browser console:

- Should be `http://localhost:8080` for local dev
- Should be `/api` for Docker

### Docker issues

```bash
# Clean everything
docker-compose down -v
docker system prune -f

# Rebuild from scratch
docker-compose build --no-cache
docker-compose up
```

## Next Steps

1. **Read the PRDs** - `docs/prd/README.md`

   - Understand the system architecture
   - See API specifications
   - Review implementation requirements

2. **Explore the Code**

   - Backend: `internal/` directory
   - Frontend: `frontend/public/` directory
   - Tests: `test/` directory

3. **Implement Handlers**

   - Most HTTP handlers return 501 (not implemented)
   - Follow PRD specifications
   - See `docs/prd/PRD-001-Authentication-Session-Management.md` to start

4. **Run Tests**
   ```bash
   make test
   ```

## API Testing (Without UI)

Use curl to test backend directly:

```bash
# 1. Authorize
curl -X POST http://localhost:8080/auth/authorize \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "client_id": "demo"}'

# 2. Get token (use session_id from step 1)
curl -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"session_id": "sess_..."}'

# 3. Get user info (use access_token from step 2)
curl http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer at_sess_..."
```

## Support

- Issues: https://github.com/your-repo/id-gateway/issues
- Docs: `docs/` directory
- PRDs: `docs/prd/` directory
- Frontend: `frontend/README.md`
