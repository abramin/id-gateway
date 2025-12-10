# Consent Management Demo

A simple, interactive UI demonstrating Credo's **PRD-002: Consent Management System**.

## Features

- **User Selection**: Switch between demo users
- **Purpose Management**: View available consent purposes with descriptions and default TTLs
- **Grant Consent**: One-click consent granting with automatic refresh
- **View Consents**: Table view of all active consents with status, timestamps, and expiry
- **Revoke Consent**: Revoke any active consent with confirmation
- **5-Minute Idempotency**: Prevents duplicate grants within the idempotency window
- **Mock Data Fallback**: Works standalone with mock data if backend is unavailable

## Tech Stack

- **Alpine.js 3.x**: Reactive UI components
- **Tailwind CSS**: Utility-first styling
- **Vanilla JavaScript**: No build tools required
- **Existing API.js**: Shared API utilities

## Files

```
frontend/public/
├── consent-demo.html          # Main HTML page
└── js/
    └── consent-demo.js        # Alpine.js component logic
```

Uses existing shared resources:

- `css/styles.css` - Shared styles (spinner, badges, tables)
- `js/api.js` - API utilities (if available)

## Running the Demo

### Option 1: With Backend Running

1. Start the Credo backend server:

   ```bash
   cd /Users/alexanderramin/Documents/GitHub/id-gateway
   make run
   # or
   go run cmd/server/main.go
   ```

2. Navigate to the demo page:
   ```
   http://localhost:8080/consent-demo.html
   ```

### Option 2: Standalone (Mock Data)

If the backend is not running, the demo will automatically fall back to mock data mode:

1. Open directly via file system or serve with any static file server:

   ```bash
   cd frontend/public
   python3 -m http.server 8000
   ```

2. Navigate to:

   ```
   http://localhost:8000/consent-demo.html
   ```

3. The UI will display a warning and use built-in mock data

## API Endpoints

The demo uses these backend endpoints (from PRD-002):

| Method | Endpoint                     | Purpose                          |
| ------ | ---------------------------- | -------------------------------- |
| `GET`  | `/api/consent/purposes`      | List available consent purposes  |
| `POST` | `/api/consent/grant`         | Grant user consent for a purpose |
| `GET`  | `/api/consent/user/:user_id` | List all consents for a user     |
| `POST` | `/api/consent/revoke`        | Revoke a user's consent          |

### Request/Response Examples

#### Grant Consent

```bash
POST /api/consent/grant
Content-Type: application/json

{
  "user_id": "alice@example.com",
  "purpose": "vc_issuance",
  "reason": "User granted via consent demo UI"
}
```

#### List User Consents

```bash
GET /api/consent/user/alice@example.com

Response:
{
  "consents": [
    {
      "id": "consent_abc123",
      "purpose": "vc_issuance",
      "status": "active",
      "granted_at": "2025-12-10T10:30:00Z",
      "expires_at": "2026-12-10T10:30:00Z"
    }
  ]
}
```

#### Revoke Consent

```bash
POST /api/consent/revoke
Content-Type: application/json

{
  "user_id": "alice@example.com",
  "purpose": "vc_issuance"
}
```

## Mock Data

When the backend is unavailable, the demo uses these mock purposes:

1. **Verifiable Credential Issuance** (`vc_issuance`)

   - Allow issuing verifiable credentials
   - Default TTL: 365 days

2. **Registry Background Check** (`registry_check`)

   - Perform background checks via registry
   - Default TTL: 90 days

3. **Analytics & Usage Data** (`analytics`)

   - Collect anonymized usage analytics
   - Default TTL: 180 days

4. **Marketing Communications** (`marketing`)
   - Send promotional emails and updates
   - Default TTL: 30 days

## User Flow

1. **Select a User**: Choose from the dropdown
2. **View Available Purposes**: Left panel shows all grantable purposes
3. **Grant Consent**: Click "Grant" button next to any purpose
4. **View Active Consents**: Right panel displays table of granted consents
5. **Monitor Expiry**: See remaining time until each consent expires
6. **Revoke Consent**: Click "Revoke" button to withdraw consent

## Key Features Demonstrated

### Idempotency Window

- Granting the same purpose twice within 5 minutes reuses the existing consent
- No duplicate audit events created
- UI automatically refreshes to show existing consent

### Consent Lifecycle

- **Active**: Currently valid consents
- **Expired**: Past their TTL expiry date
- **Revoked**: Explicitly withdrawn by user

### Real-time Updates

- All actions trigger automatic UI refresh
- Success/error notifications with auto-dismiss
- Loading states for better UX

## Customization

### Adding New Purposes

Edit the `mockPurposes` array in `consent-demo.js`:

```javascript
mockPurposes: [
  {
    id: "custom_purpose",
    name: "Custom Purpose Name",
    description: "Description of what this allows",
    default_ttl_hours: 720, // 30 days
  },
];
```

### Changing Demo Users

Edit the `users` array in `consent-demo.js`:

```javascript
users: [{ id: "user@example.com", name: "User Name" }];
```

## Integration with Backend

To wire this up to your actual Credo backend:

1. **Implement the purposes endpoint** (currently not in main codebase):

   ```go
   // GET /api/consent/purposes
   // Returns list of available consent purposes with metadata
   ```

2. **Update the consent handler** to support the grant/revoke format:

   ```go
   // POST /api/consent/grant
   // POST /api/consent/revoke
   ```

3. **Ensure CORS is configured** if running on different ports

4. **Add authentication** for production use (currently demo mode)

## Testing

### Manual Testing Checklist

- [ ] Switch between users - consents should refresh
- [ ] Grant consent - appears in active consents table
- [ ] Grant same consent twice - shows idempotency message
- [ ] Revoke consent - status changes to revoked
- [ ] Check expiry times - countdown updates
- [ ] Disconnect backend - mock data mode activates
- [ ] Reconnect backend - switches back to real data

### Browser Console

The demo logs all API interactions to the console:

```javascript
console.log("Consent Demo initialized");
console.warn("Backend unavailable, using mock data");
console.error("Failed to grant consent");
```

## Troubleshooting

### Backend Connection Issues

If you see "Backend unavailable" warnings:

1. Check if the backend is running: `curl http://localhost:8080/health`
2. Verify the port matches your backend configuration
3. Check browser console for CORS errors

### Mock Data Not Appearing

If mock data doesn't load:

1. Check browser console for JavaScript errors
2. Verify Alpine.js loaded: check for `Alpine` in console
3. Ensure all script tags loaded properly

### Consents Not Updating

If granted consents don't appear:

1. Check Network tab for API responses
2. Verify backend endpoints match expected format
3. Look for error notifications in the UI

## Future Enhancements

- [ ] Custom TTL input when granting consent
- [ ] Filter/search consents by purpose or status
- [ ] Export consent history as CSV/JSON
- [ ] WebSocket updates for real-time consent changes
- [ ] Consent history timeline view
- [ ] Bulk consent operations

## Related Documentation

- [PRD-002: Consent Management](../../docs/prd/PRD-002-Consent-Management.md)
- [Architecture Documentation](../../docs/architecture.md)
- [OAuth Demo](./demo.html)

## License

Part of the Credo Identity Gateway project.
