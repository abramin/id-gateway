# Frontend Architecture

## Overview

The ID Gateway frontend is a **zero-build, CDN-based single-page application** built with Alpine.js and Tailwind CSS. It demonstrates the capabilities of the identity verification gateway through two distinct interfaces.

## Design Principles

### 1. Zero Build Complexity
- No webpack, vite, or build tools
- Direct CDN imports (Alpine.js, Tailwind CSS)
- Serves static files with nginx
- Instant development setup

### 2. Separation of Concerns
```
Presentation Layer (HTML)
    ↓
State Management (Alpine.js)
    ↓
API Client (api.js)
    ↓
Backend API (Go)
```

### 3. Progressive Enhancement
- Works without JavaScript (basic HTML)
- Enhanced with Alpine.js reactivity
- Styled with Tailwind utilities

## File Structure

```
frontend/
├── public/                  # Static assets (served by nginx)
│   ├── index.html          # User portal (main interface)
│   ├── admin.html          # Admin dashboard
│   ├── css/
│   │   └── styles.css      # Custom CSS (animations, tables, etc.)
│   └── js/
│       ├── api.js          # API client (HTTP requests)
│       ├── app.js          # User portal logic
│       └── admin.js        # Admin dashboard logic
├── Dockerfile              # Nginx container config
├── nginx.conf              # Reverse proxy + static serving
└── Makefile               # Development helpers
```

## Components

### API Client (`js/api.js`)

**Purpose:** Abstract HTTP communication with backend

**Features:**
- Environment detection (dev vs docker vs prod)
- Token management (localStorage)
- Error handling
- RESTful endpoint methods

**Pattern:**
```javascript
class APIClient {
    async authorize(email) { ... }
    async getToken(sessionId) { ... }
    async getUserInfo() { ... }
    // ... more methods per PRD specs
}
```

### User Portal (`index.html` + `app.js`)

**Purpose:** End-user interface for identity verification flow

**State Management:**
```javascript
Alpine.data('app', () => ({
    // Authentication
    isAuthenticated: false,
    userInfo: null,

    // Business logic
    consentPurposes: [...],
    citizenRecord: null,
    decision: null,

    // Methods
    async login() { ... },
    async grantConsent() { ... },
    async evaluateDecision() { ... }
}))
```

**User Flow:**
1. Login (email-only, auto-create user)
2. Grant consent (purpose-based)
3. Identity verification (citizen + sanctions)
4. Issue VC (AgeOver18 credential)
5. Evaluate decision (pass/fail/conditional)
6. Data rights (export/delete)

### Admin Dashboard (`admin.html` + `admin.js`)

**Purpose:** Real-time monitoring and compliance visualization

**Features:**
- Live statistics dashboard
- Recent decisions feed
- Active user monitoring
- Consent analytics
- Regulated mode comparison
- Live audit stream with filtering

**Mock Data Strategy:**
```javascript
// Currently uses mock data generators
// To be replaced with real API calls when backend admin endpoints exist
generateMockDecisions(count)
generateMockUsers(count)
generateMockAuditEvents(count)
```

## State Management

### Alpine.js Reactive Data

Alpine.js provides fine-grained reactivity:

```html
<div x-data="app">
    <span x-text="userEmail"></span>          <!-- Reactive text -->
    <input x-model="email">                   <!-- Two-way binding -->
    <button @click="login">Login</button>     <!-- Event handling -->
    <div x-show="isAuthenticated">...</div>   <!-- Conditional rendering -->
</div>
```

### Persistence Strategy

| Data | Storage | Reason |
|------|---------|--------|
| Access Token | localStorage | Need across page reloads |
| ID Token | localStorage | Optional, for reference |
| User Email | localStorage | Show "logged in as..." |
| Session State | Alpine.js memory | Reactive, cleared on logout |

## API Integration

### Environment-Aware URLs

```javascript
const API_BASE_URL = (() => {
    if (window.location.port === '3000') {
        return '/api';  // Docker: nginx proxy to backend
    }
    if (window.location.hostname === 'localhost') {
        return 'http://localhost:8080';  // Dev: direct backend
    }
    return '';  // Production: same origin
})();
```

### Error Handling Pattern

```javascript
try {
    const data = await api.someMethod();
    this.success = 'Operation successful';
} catch (err) {
    console.error('Operation failed:', err);
    this.error = err.message || 'Operation failed';
} finally {
    this.loading = false;
}
```

## Styling Strategy

### Tailwind Utility-First

- 95% Tailwind utility classes
- 5% custom CSS in `styles.css`

**Example:**
```html
<div class="bg-white rounded-lg shadow-md p-6">
    <h3 class="text-lg font-bold text-gray-900 mb-4">Title</h3>
</div>
```

### Custom CSS (`styles.css`)

Used for:
- Animations (spinner, pulse, fadeOut)
- Hover effects (cards)
- Table styling (audit log)
- Scrollbar customization

## Docker Architecture

```
┌─────────────────┐
│   User Browser  │
└────────┬────────┘
         │ http://localhost:3000
         ▼
┌─────────────────┐
│  Nginx (port 80)│
│  - Serves /     │ (static HTML/CSS/JS)
│  - Proxies /api│ → backend:8080
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Backend (Go)    │
│ Port 8080       │
│ API endpoints   │
└─────────────────┘
```

**Benefits:**
- Single domain (no CORS)
- Clean URLs (/api/auth/login)
- Production-ready setup

## Security Considerations

### Current Demo Security

⚠️ **Not Production-Ready**

| Feature | Demo | Production Needed |
|---------|------|-------------------|
| Token Storage | localStorage | HttpOnly cookies |
| HTTPS | No | Required |
| CSRF Protection | No | Tokens required |
| XSS Protection | Basic | CSP headers |
| Input Validation | Client-side only | Server-side required |

### CORS Strategy

Docker (nginx proxy):
- No CORS needed (same origin)

Local dev (different ports):
- Backend must set CORS headers
- Allow `http://localhost:8000`

## Performance

### Optimizations

1. **CDN Resources**
   - Alpine.js (15KB) from jsdelivr CDN
   - Tailwind CSS from CDN
   - Browser caching

2. **Lazy Loading**
   - Alpine.js deferred with `defer` attribute
   - Images lazy-loaded (none yet)

3. **Polling vs WebSockets**
   - Admin dashboard: 5-second polling
   - Future: WebSocket for real-time updates

### Load Times

- Initial load: ~50-100ms (CDN cached)
- Page transitions: Instant (SPA)
- API calls: Depends on backend

## Testing Strategy

### Manual Testing Checklist

**User Portal:**
- [ ] Login creates user
- [ ] Token stored in localStorage
- [ ] Consent toggle works
- [ ] Registry checks display results
- [ ] VC issuance shows credential
- [ ] Decision evaluation shows outcome
- [ ] Data export downloads JSON
- [ ] Delete account clears session

**Admin Dashboard:**
- [ ] Stats update on refresh
- [ ] Decisions feed shows color coding
- [ ] Active users list populates
- [ ] Consent stats calculate percentages
- [ ] Regulated mode comparison visible
- [ ] Audit stream filters work
- [ ] Live updates every 5 seconds

### Browser Testing

Tested on:
- Chrome 120+
- Firefox 121+
- Safari 17+
- Edge 120+

## Future Enhancements

### Short Term
- [ ] Real backend integration (replace mocks)
- [ ] WebSocket for live updates
- [ ] Admin authentication
- [ ] Error boundary handling

### Medium Term
- [ ] Dark mode toggle
- [ ] Mobile responsive tables
- [ ] Export charts/graphs
- [ ] i18n support

### Long Term
- [ ] PWA capabilities (offline)
- [ ] E2E testing (Playwright)
- [ ] Build step for optimization
- [ ] Component library extraction

## Development Workflow

### Adding a New Feature

1. **Update API Client**
   ```javascript
   // js/api.js
   async newFeature(params) {
       return await this.request('/new/endpoint', {
           method: 'POST',
           body: JSON.stringify(params),
       });
   }
   ```

2. **Add State to Alpine Component**
   ```javascript
   // js/app.js or admin.js
   newFeatureData: null,
   async callNewFeature() {
       this.newFeatureData = await api.newFeature({...});
   }
   ```

3. **Add UI in HTML**
   ```html
   <button @click="callNewFeature">Click</button>
   <div x-show="newFeatureData">
       <span x-text="newFeatureData.result"></span>
   </div>
   ```

### Debugging Tips

**API Issues:**
```javascript
// Check console for:
console.log('API Base URL:', api.baseURL);
console.log('Token:', localStorage.getItem('access_token'));
```

**State Issues:**
```html
<!-- Add to HTML for debugging -->
<div x-data="app">
    <pre x-text="JSON.stringify($data, null, 2)"></pre>
</div>
```

**Network Issues:**
- Check browser DevTools Network tab
- Verify backend is running
- Check CORS errors

## Contributing

When adding new features:
1. Follow existing patterns (API client → Alpine state → HTML)
2. Use Tailwind classes (avoid custom CSS)
3. Handle errors gracefully
4. Update this documentation
5. Test in both dev and Docker modes

## References

- [Alpine.js Docs](https://alpinejs.dev/)
- [Tailwind CSS Docs](https://tailwindcss.com/)
- [Nginx Config Reference](https://nginx.org/en/docs/)
- Backend API: `../docs/prd/README.md`
