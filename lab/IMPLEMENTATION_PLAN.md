# Attack Lab Implementation Plan

## Executive Summary

Implement three interconnected educational modules for OAuth security learning:
1. **Control Panel** - Toggle-based defense learning
2. **Dual Perspective** - Story-driven attacker/defender scenarios
3. **Request Forge** - Technical hands-on sandbox

All modules share common infrastructure and can be accessed from a central index page.

---

## Framework Decision

### Recommendation: **Stay with Alpine.js**

Alpine.js is sufficient for this project because:
- Existing codebase already uses it consistently
- No build step required (CDN-based)
- `Alpine.store()` handles shared state across modules
- Component extraction via `Alpine.data()` enables reuse
- Complexity level matches our needs

**Enhancements needed:**
- Add `Alpine.store()` for global state (security config, mock API)
- Extract reusable components into separate JS files
- Use hash-based routing for SPA-like navigation within modules

**If we needed more**, I would suggest **Petite-Vue** (Vue's 6kb alternative), but Alpine is appropriate here.

---

## Shared Components Analysis

### What All 3 Modules Need

| Component | Control Panel | Dual Perspective | Request Forge |
|-----------|--------------|------------------|---------------|
| OAuth Flow Diagram | Attack results viz | Story animations | Flow builder |
| Request/Response Viewer | Attack output | Step details | Core feature |
| JWT Decoder | Token inspection | Payload analysis | JWT toolkit |
| Security Controls | Primary UI | Defender mode | Compare mode |
| Mock API | All attacks | Scenario runner | Request sender |

### Extracted Shared Components

```
┌─────────────────────────────────────────────────────────────────┐
│                      SHARED LAYER                               │
├─────────────────────────────────────────────────────────────────┤
│  Alpine Stores                                                  │
│  ├── configStore     - Security settings (PKCE, aud, etc.)     │
│  ├── mockApiStore    - Mock responses, switchable to real API  │
│  └── scenarioStore   - Attack/scenario definitions             │
├─────────────────────────────────────────────────────────────────┤
│  Reusable Components                                            │
│  ├── oauthDiagram    - SVG flow visualization (from attacks.js)│
│  ├── requestViewer   - HTTP request/response display           │
│  ├── jwtDecoder      - Token parsing with annotations          │
│  ├── securityPanel   - Toggle switches for security controls   │
│  └── attackRunner    - Execute attacks, return results         │
├─────────────────────────────────────────────────────────────────┤
│  Utilities                                                      │
│  ├── jwt.js          - JWT encode/decode/validate              │
│  ├── formatting.js   - JSON pretty print, time formatting      │
│  └── animations.js   - Anime.js wrappers for diagrams          │
└─────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
lab/
├── index.html                      # Landing page - module selection
├── control-panel.html              # Module 1: Defense Control Panel
├── dual-perspective.html           # Module 2: Story-driven scenarios
├── request-forge.html              # Module 3: Technical sandbox
│
├── css/
│   ├── shared.css                  # Base theme, typography, layout
│   ├── components.css              # Reusable component styles
│   ├── control-panel.css           # Module 1 specific styles
│   ├── dual-perspective.css        # Module 2 specific styles
│   └── request-forge.css           # Module 3 specific styles
│
├── js/
│   ├── stores/
│   │   ├── config-store.js         # Security configuration state
│   │   ├── mock-api-store.js       # Mock API with response templates
│   │   └── scenario-store.js       # Attack definitions & stories
│   │
│   ├── components/
│   │   ├── oauth-diagram.js        # Reusable OAuth flow visualization
│   │   ├── request-viewer.js       # Request/response display component
│   │   ├── jwt-decoder.js          # JWT parsing and annotation
│   │   ├── security-panel.js       # Security control toggles
│   │   ├── attack-runner.js        # Execute and report attacks
│   │   └── step-navigator.js       # Step-through navigation
│   │
│   ├── utils/
│   │   ├── jwt.js                  # JWT utilities (from demo.js)
│   │   ├── formatting.js           # Pretty printing, timestamps
│   │   └── animations.js           # Anime.js animation helpers
│   │
│   ├── modules/
│   │   ├── control-panel.js        # Module 1 logic
│   │   ├── dual-perspective.js     # Module 2 logic
│   │   └── request-forge.js        # Module 3 logic
│   │
│   └── data/
│       ├── attack-definitions.js   # Extended attack specs
│       ├── story-scenarios.js      # Narrative scenarios for Module 2
│       └── mock-responses.js       # Mock API response templates
│
├── attacker-ui/                    # Existing (keep for reference)
├── resource-server/                # Existing naive resource server
├── credo-config/                   # Existing config profiles
└── docker-compose.yaml             # Existing orchestration
```

---

## Mock API Design

The mock API layer abstracts backend calls so we can:
1. Develop UI without running Credo
2. Test edge cases and error states
3. Easily switch to real API later

### Mock API Store Structure

```javascript
Alpine.store('mockApi', {
    // Mode: 'mock' or 'live'
    mode: 'mock',
    baseUrl: 'http://localhost:8080',

    // Security configuration affects mock responses
    config: Alpine.store('config'),

    // Core OAuth endpoints
    async authorize(params) {
        if (this.mode === 'mock') {
            return this.mockAuthorize(params);
        }
        return this.liveAuthorize(params);
    },

    async token(params) { /* ... */ },
    async userinfo(token) { /* ... */ },

    // Attack-specific endpoints
    async replayToken(token, targetAudience) { /* ... */ },
    async testRedirectUri(maliciousUri) { /* ... */ },

    // Mock response generators
    mockAuthorize(params) {
        const config = Alpine.store('config');

        // If PKCE required but not provided, fail
        if (config.requirePkce && !params.code_challenge) {
            return {
                success: false,
                error: 'invalid_request',
                error_description: 'PKCE code_challenge required'
            };
        }

        // Generate mock authorization code
        return {
            success: true,
            code: 'mock_authz_' + Math.random().toString(36).substr(2, 16),
            state: params.state,
            redirect_uri: params.redirect_uri
        };
    }
});
```

### Mock Response Templates

```javascript
// mock-responses.js
export const MOCK_RESPONSES = {
    authorize: {
        success: {
            code: () => 'authz_' + randomId(),
            state: (params) => params.state
        },
        pkce_required: {
            error: 'invalid_request',
            error_description: 'code_challenge is required for public clients'
        },
        invalid_redirect: {
            error: 'invalid_request',
            error_description: 'redirect_uri does not match registered URIs'
        }
    },

    token: {
        success: {
            access_token: () => generateMockJwt('access'),
            id_token: () => generateMockJwt('id'),
            token_type: 'Bearer',
            expires_in: 900
        },
        invalid_code: {
            error: 'invalid_grant',
            error_description: 'Authorization code is invalid or expired'
        },
        pkce_mismatch: {
            error: 'invalid_grant',
            error_description: 'code_verifier does not match code_challenge'
        }
    },

    resource_server: {
        success: {
            data: { message: 'Protected resource accessed', user: 'victim@example.com' }
        },
        invalid_audience: {
            // This succeeds when audience validation is OFF (vulnerable)
            data: { message: 'Resource accessed (audience not validated!)' }
        },
        audience_rejected: {
            error: 'invalid_token',
            error_description: 'Token audience does not match this resource server'
        }
    }
};
```

---

## Security Configuration Store

Central store for security control states, shared across all modules.

```javascript
// config-store.js
Alpine.store('config', {
    // PKCE Configuration
    requirePkce: true,
    pkceMethod: 'S256',  // or 'plain'

    // Redirect URI Validation
    strictRedirectUri: true,
    allowWildcardRedirects: false,
    httpsOnlyRedirects: true,

    // Token Security
    validateAudience: true,
    shortTokenLifetime: true,  // 15min vs 1hr
    requireStateParam: true,

    // Advanced
    enableRefreshTokenRotation: true,
    bindTokenToDevice: false,

    // Computed security score (0-100)
    get securityScore() {
        let score = 0;
        if (this.requirePkce) score += 20;
        if (this.strictRedirectUri) score += 15;
        if (this.httpsOnlyRedirects) score += 10;
        if (this.validateAudience) score += 20;
        if (this.shortTokenLifetime) score += 10;
        if (this.requireStateParam) score += 15;
        if (this.enableRefreshTokenRotation) score += 5;
        if (this.bindTokenToDevice) score += 5;
        return score;
    },

    // Which attacks are possible with current config
    get vulnerabilities() {
        const vulns = [];
        if (!this.requirePkce) vulns.push('code_interception');
        if (!this.strictRedirectUri) vulns.push('redirect_manipulation');
        if (!this.validateAudience) vulns.push('token_replay');
        if (!this.requireStateParam) vulns.push('csrf_callback');
        return vulns;
    },

    // Preset configurations
    applyPreset(preset) {
        const presets = {
            insecure: {
                requirePkce: false,
                strictRedirectUri: false,
                validateAudience: false,
                requireStateParam: false,
                shortTokenLifetime: false
            },
            partial: {
                requirePkce: true,
                strictRedirectUri: false,
                validateAudience: false,
                requireStateParam: true,
                shortTokenLifetime: true
            },
            secure: {
                requirePkce: true,
                strictRedirectUri: true,
                validateAudience: true,
                requireStateParam: true,
                shortTokenLifetime: true,
                httpsOnlyRedirects: true,
                enableRefreshTokenRotation: true
            }
        };
        Object.assign(this, presets[preset]);
    }
});
```

---

## Module-Specific Designs

### Module 1: Control Panel

**Core Interaction Pattern:**
1. User toggles security controls
2. System updates security score
3. User clicks "Run All Attacks"
4. Each attack runs against current config
5. Results show pass/fail with explanation

**Key Components:**
- Security toggle panel (left side)
- Security score meter
- Attack result cards (right side)
- Explanation modal on card click

**State:**
```javascript
Alpine.data('controlPanel', () => ({
    attackResults: [],
    running: false,
    selectedAttack: null,

    async runAllAttacks() {
        this.running = true;
        this.attackResults = [];

        for (const attack of ATTACK_DEFINITIONS) {
            const result = await Alpine.store('attackRunner').execute(attack.id);
            this.attackResults.push({
                ...attack,
                ...result,
                blocked: !result.success,
                blockedBy: result.blockedBy
            });
        }

        this.running = false;
    }
}));
```

---

### Module 2: Dual Perspective

**Core Interaction Pattern:**
1. User selects a scenario
2. Chooses perspective (Attacker/Defender)
3. Steps through narrative with decision points
4. Sees outcome based on security config
5. Can switch perspective and replay

**Key Components:**
- Scenario selector sidebar
- Perspective toggle (Attacker/Defender)
- Story panel with narrative text
- Animated OAuth diagram
- Decision buttons at branch points
- Outcome summary

**Scenario Schema:**
```javascript
// story-scenarios.js
export const STORY_SCENARIOS = [
    {
        id: 'pkce_bypass',
        title: 'The PKCE Bypass',
        summary: 'A public client without PKCE protection',
        difficulty: 'beginner',

        attacker: {
            intro: "You've discovered a web application that uses OAuth 2.0...",
            steps: [
                {
                    id: 'recon',
                    narrative: "First, you examine the OAuth authorization request...",
                    diagram: { action: 'showFlow', nodes: ['user', 'client', 'authServer'] },
                    choices: [
                        { text: "Check for PKCE parameters", next: 'check_pkce' },
                        { text: "Try redirect manipulation", next: 'wrong_path' }
                    ]
                },
                {
                    id: 'check_pkce',
                    narrative: "You notice there's no code_challenge parameter...",
                    condition: (config) => !config.requirePkce,
                    onTrue: { next: 'intercept' },
                    onFalse: {
                        narrative: "PKCE is enabled! The code_challenge blocks this attack.",
                        outcome: 'blocked'
                    }
                },
                // ... more steps
            ]
        },

        defender: {
            intro: "You're the security engineer reviewing OAuth configuration...",
            steps: [
                {
                    id: 'review',
                    narrative: "You open the client configuration panel...",
                    showControls: ['requirePkce', 'pkceMethod'],
                    hint: "Public clients should always require PKCE"
                },
                // ... configuration steps
            ]
        }
    }
];
```

---

### Module 3: Request Forge

**Core Interaction Pattern:**
1. User selects endpoint (authorize, token, userinfo)
2. Fills in request parameters via form
3. Sees real-time security analysis
4. Sends request to mock/live API
5. Inspects response with annotations
6. Can modify JWT claims directly

**Key Components:**
- Endpoint selector tabs
- Parameter form with annotations
- Security analysis sidebar
- Request/Response split view
- JWT decoder/encoder panel
- Compare mode toggle

**State:**
```javascript
Alpine.data('requestForge', () => ({
    activeEndpoint: 'authorize',

    endpoints: {
        authorize: {
            method: 'GET',
            path: '/auth/authorize',
            params: {
                response_type: { value: 'code', required: true, editable: false },
                client_id: { value: 'demo-client', required: true },
                redirect_uri: { value: 'https://app.example.com/callback', required: true },
                scope: { value: 'openid profile', required: true },
                state: { value: '', required: true, generate: true },
                code_challenge: { value: '', required: false, pkce: true },
                code_challenge_method: { value: 'S256', required: false, pkce: true }
            }
        },
        token: { /* ... */ },
        userinfo: { /* ... */ }
    },

    request: null,
    response: null,
    compareMode: false,
    compareResponse: null,  // Response with alternate config

    // Security analysis of current request
    get securityAnalysis() {
        const issues = [];
        const params = this.endpoints[this.activeEndpoint].params;

        if (!params.code_challenge?.value) {
            issues.push({
                severity: 'high',
                message: 'No PKCE code_challenge - vulnerable to code interception',
                fix: 'Add code_challenge parameter'
            });
        }

        if (!params.state?.value) {
            issues.push({
                severity: 'high',
                message: 'Missing state parameter - vulnerable to CSRF',
                fix: 'Generate random state value'
            });
        }

        // ... more checks
        return issues;
    },

    async sendRequest() {
        this.request = this.buildRequest();
        this.response = await Alpine.store('mockApi')[this.activeEndpoint](this.request);

        if (this.compareMode) {
            // Run same request with opposite config
            const altConfig = this.getAlternateConfig();
            this.compareResponse = await Alpine.store('mockApi')[this.activeEndpoint](
                this.request,
                altConfig
            );
        }
    }
}));
```

---

## Implementation Phases

### Phase 1: Shared Infrastructure (Day 1)
- [ ] Create base file structure
- [ ] Implement `config-store.js`
- [ ] Implement `mock-api-store.js` with response templates
- [ ] Create `shared.css` with theme variables
- [ ] Extract JWT utilities to `jwt.js`
- [ ] Create `request-viewer.js` component
- [ ] Create `security-panel.js` component

### Phase 2: Index Page (Day 1)
- [ ] Create `index.html` with module cards
- [ ] Style module selection UI
- [ ] Add module descriptions and previews

### Phase 3: Control Panel - Module 1 (Day 2)
- [ ] Create `control-panel.html` structure
- [ ] Implement security toggle panel
- [ ] Create security score visualization
- [ ] Implement attack runner with results display
- [ ] Add explanation panels for blocked attacks
- [ ] Style with `control-panel.css`

### Phase 4: Dual Perspective - Module 2 (Day 2-3)
- [ ] Create `dual-perspective.html` structure
- [ ] Define story scenarios in `story-scenarios.js`
- [ ] Implement scenario selector
- [ ] Create perspective toggle (Attacker/Defender)
- [ ] Build narrative step engine with branching
- [ ] Integrate OAuth diagram animations
- [ ] Add outcome summary view
- [ ] Style with `dual-perspective.css`

### Phase 5: Request Forge - Module 3 (Day 3)
- [ ] Create `request-forge.html` structure
- [ ] Build endpoint selector tabs
- [ ] Create parameter form with annotations
- [ ] Implement security analysis sidebar
- [ ] Build response inspector with JWT highlighting
- [ ] Add compare mode functionality
- [ ] Create JWT encoder/decoder panel
- [ ] Style with `request-forge.css`

### Phase 6: Polish & Integration (Day 4)
- [ ] Test all modules end-to-end
- [ ] Add loading states and error handling
- [ ] Implement smooth transitions between modules
- [ ] Add keyboard navigation
- [ ] Create "back to index" navigation
- [ ] Write usage documentation

---

## API Migration Path

When ready to connect to real Credo:

1. **Set mode in mock-api-store:**
   ```javascript
   Alpine.store('mockApi').mode = 'live';
   Alpine.store('mockApi').baseUrl = 'http://localhost:8080';
   ```

2. **Credo needs new endpoints:**
   - `GET /demo/config` - Get current security settings
   - `POST /demo/config` - Update security settings for demo mode
   - Existing `/auth/*` endpoints work as-is

3. **Resource server integration:**
   - Lab's `resource-server/main.go` already exists
   - Toggle audience validation via env var or endpoint

---

## Dependencies

**CDN-based (no build step):**
- Alpine.js 3.x - Reactivity framework
- Anime.js 3.2.x - Animation library
- (Optional) Highlight.js - Syntax highlighting for JSON/JWT

**No additional frameworks needed.**

---

## Open Questions

1. **Persistence**: Should security config persist across page reloads? (localStorage)
2. **Progress tracking**: Should Module 2 save scenario progress?
3. **Theming**: Support light mode or dark-only?
4. **Mobile**: Full mobile support or desktop-focused?

---

## Next Steps

1. Review and approve this plan
2. Begin Phase 1: Shared Infrastructure
3. Iterate based on feedback after each module
