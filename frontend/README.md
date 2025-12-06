# Credo - Frontend UI

Demo UI for Credo identity verification system. Features two views:

1. **User Portal** (`index.html`) - Login, consent management, identity verification, VCs, decisions, data rights
2. **Admin Dashboard** (`admin.html`) - Real-time monitoring, audit logs, decision tracking, compliance view

## Documentation

- App architecture & frontend stack: [ARCHITECTURE.md](ARCHITECTURE.md)
- Attack paths (OAuth2 threats): [ATTACK_PATHS.md](ATTACK_PATHS.md)
- Attack module implementation summary: [ATTACK_MODULE_SUMMARY.md](ATTACK_MODULE_SUMMARY.md)

## Technology Stack

- **Alpine.js** - Lightweight reactive framework (15KB)
- **Tailwind CSS** - Utility-first CSS via CDN
- **Vanilla JavaScript** - No build step required
- **Nginx** - Static file serving in production

## Running the Frontend

### Option 1: Docker (Recommended)

From the root directory:

```bash
# Start both frontend and backend
docker-compose up --build

# Frontend available at: http://localhost:3000
# Backend API at: http://localhost:8080
```

### Option 2: Development (Local)

Serve the `public/` directory with any static file server:

```bash
# Using Python
cd frontend/public
python3 -m http.server 8000

# Using Node.js (http-server)
npx http-server frontend/public -p 8000

# Using PHP
cd frontend/public
php -S localhost:8000
```

**Note:** When running locally, ensure the backend is running on `http://localhost:8080`

## Features

### User Portal

#### Authentication

- Email-only login (no password for demo)
- Automatic user creation
- Session management with tokens

#### Consent Management

- Grant/revoke consent for different purposes:
  - Registry checks
  - VC issuance
  - Decision evaluation
- Visual consent cards with status

#### Identity Verification

- Citizen registry lookup
- Sanctions screening
- Shows PII stripping in regulated mode

#### Verifiable Credentials

- Issue "AgeOver18" credentials
- View credential details
- Credential-based decisions

#### Decision Engine

- Evaluate authorization decisions
- Multiple purposes supported
- Visual decision outcomes (pass/fail/conditional)

#### Data Rights (GDPR)

- Export all personal data
- Delete account
- See what's deleted vs retained

### Admin Dashboard

#### Statistics

- Total users
- Active sessions
- VCs issued
- Decisions made

#### Recent Decisions

- Real-time decision feed
- Color-coded outcomes
- Detailed reasons

#### Active Users

- Current sessions
- User activity
- Session count

#### Consent Overview

- Consent grant rates
- Purpose breakdown
- Visual progress bars

#### Regulated Mode Comparison

- Side-by-side data view
- Shows PII stripping
- Demonstrates data minimization

#### Live Audit Stream

- Real-time event feed
- Filterable by action type
- Complete audit trail

## Configuration

### API Endpoints

The frontend expects these backend endpoints (per PRD specs):

**Auth (PRD-001):**

- `POST /auth/authorize`
- `POST /auth/token`
- `GET /auth/userinfo`

**Consent (PRD-002):**

- `POST /auth/consent`
- `POST /auth/consent/revoke`

**Registry (PRD-003):**

- `POST /registry/citizen`
- `POST /registry/sanctions`

**VC (PRD-004):**

- `POST /vc/issue`
- `POST /vc/verify`

**Decision (PRD-005):**

- `POST /decision/evaluate`

**Data Rights (PRD-006, PRD-007):**

- `GET /me/data-export`
- `DELETE /me`

### Environment Variables

The frontend automatically adapts to the environment:

- **Docker (port 3000):** Uses `/api` proxy → nginx → backend
- **Local dev:** Direct calls to `http://localhost:8080`
- **Production:** Same-origin requests

## Development

### File Structure

```
frontend/
├── public/
│   ├── index.html         # User portal
│   ├── admin.html         # Admin dashboard
│   ├── css/
│   │   └── styles.css     # Custom styles
│   └── js/
│       ├── api.js         # API client
│       ├── app.js         # User portal logic
│       └── admin.js       # Admin dashboard logic
├── Dockerfile             # Production nginx container
├── nginx.conf             # Nginx configuration
└── README.md              # This file
```

### Adding New Features

1. **New API Endpoint:**

   - Add method to `js/api.js`
   - Call from `app.js` or `admin.js`

2. **New UI Component:**

   - Add HTML in `index.html` or `admin.html`
   - Add Alpine.js reactive logic in corresponding JS file

3. **New Styles:**
   - Add to `css/styles.css`
   - Or use Tailwind utility classes

## Mock Data

The admin dashboard currently uses mock data for demonstration purposes. When the backend is fully implemented:

1. Replace mock data generators in `admin.js`
2. Add real API calls for admin endpoints
3. Implement WebSocket for real-time updates (optional)

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

## Known Limitations

- No build step (relies on CDN for Alpine.js and Tailwind)
- Admin dashboard uses mock data (backend admin endpoints not yet implemented)
- No WebSocket support yet (uses polling for live updates)
- LocalStorage for token management (suitable for demo, not production)

## Future Enhancements

- [ ] WebSocket for real-time audit stream
- [ ] Admin authentication
- [ ] Dark mode toggle
- [ ] Export charts/reports
- [ ] Mobile-responsive tables
- [ ] Offline support (PWA)
- [ ] i18n support

## Security Notes

⚠️ **This is a demo UI.** Do not use in production without:

- HTTPS/TLS
- Secure token storage (HttpOnly cookies)
- CSRF protection
- XSS sanitization
- Content Security Policy headers
- Rate limiting

## License

Part of Credo project.
