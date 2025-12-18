# OAuth 2.0 Attack Paths Module

## Overview

The Attack Paths module is an interactive educational tool that demonstrates common security vulnerabilities in OAuth 2.0 Authorization Code Flow. It uses visual diagram animations and step-by-step narratives to show how attacks work and how to prevent them.

Related docs:

- Frontend overview and entry points: [README.md](README.md)
- Frontend architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Implementation summary: [ATTACK_MODULE_SUMMARY.md](ATTACK_MODULE_SUMMARY.md)

## Features

- **6 Attack Scenarios**: Covers critical OAuth 2.0 vulnerabilities specific to the Authorization Code Flow
- **Interactive Visualizations**: Animated diagrams showing attack progression
- **Step-by-Step Walkthrough**: Detailed breakdown of each attack stage
- **Mitigation Guidance**: Practical security recommendations for each vulnerability
- **Lightweight Dependencies**: Uses Alpine.js and anime.js (same stack as the normal flow demo)

## File Structure

```
frontend/public/
├── attacks.html              # Main attack paths page
├── css/
│   └── attacks.css           # Attack-specific styles and animations
└── js/
    ├── attack-scenarios.js   # Attack definitions (JSON specs)
    └── attacks.js            # Controller and animation logic
```

## Attack Scenarios Included

### 1. Authorization Code Interception

- **Severity**: High
- **Category**: Code Flow Attacks
- **Description**: Attacker intercepts the authorization code during redirect
- **Key Mitigations**: PKCE, short code expiration, HTTPS only

### 2. Redirect URI Manipulation

- **Severity**: Critical
- **Category**: Code Flow Attacks
- **Description**: Attacker manipulates redirect_uri to steal authorization code
- **Key Mitigations**: Exact URI matching, pre-registration, HTTPS enforcement

### 3. Token Leakage via Browser Storage

- **Severity**: High
- **Category**: Token Security
- **Description**: Tokens exposed through localStorage/sessionStorage
- **Key Mitigations**: httpOnly cookies, CSP, Backend-for-Frontend pattern

### 4. Token Leakage via Logs & Referrer Headers

- **Severity**: Medium
- **Category**: Token Security
- **Description**: Tokens leaked through logs, URLs, or HTTP referer headers
- **Key Mitigations**: Authorization header usage, log sanitization, Referrer-Policy

### 5. Scope Escalation Attack

- **Severity**: Medium
- **Category**: Authorization
- **Description**: Attacker manipulates scope parameter for unauthorized permissions
- **Key Mitigations**: Clear consent screens, scope validation, audit logging

### 6. CSRF on Callback

- **Severity**: High
- **Category**: Code Flow Attacks
- **Description**: Attacker forces victim to complete OAuth flow with attacker's code
- **Key Mitigations**: State parameter validation, nonce, SameSite cookies

## How to Use

### Accessing the Module

Navigate to: `http://localhost:8080/attacks.html` (or your frontend URL)

### Navigation Flow

1. **Select an Attack**: Click on any attack scenario from the left sidebar
2. **Step Through**: Use "Next" and "Previous" buttons to walk through the attack
3. **Review Mitigations**: Scroll down to see prevention strategies
4. **Reset**: Click "Reset" to restart the animation

### Diagram Elements

- **Blue Nodes**: Normal OAuth flow participants
- **Red Node with Skull**: Attacker
- **Blue Arrows**: Normal OAuth communication
- **Red Arrows**: Attack vectors
- **Purple Arrows**: Compromised access
- **Dashed Lines**: Intercepted or injected communication

## Adding New Attack Scenarios

### Step 1: Define the Attack Spec

Edit `js/attack-scenarios.js` and add a new object to the `ATTACK_SCENARIOS` array:

```javascript
{
  id: 'unique_attack_id',
  title: 'Attack Name',
  category: 'Attack Category',
  severity: 'critical|high|medium',
  description: 'Brief description of the attack',
  steps: [
    {
      text: 'Step 1 description',
      highlight: 'normal|attack|compromised'
    },
    {
      text: 'Step 2 description',
      highlight: 'attack'
    }
    // ... more steps
  ],
  diagramActions: [
    {
      step: 0,
      action: 'showFlow|highlightAttack|showAttack|showCompromised',
      nodes: ['user', 'client', 'authServer', 'resourceServer', 'attacker'],
      arrows: [
        {
          from: 'user',
          to: 'authServer',
          label: 'Arrow label',
          color: 'normal|attack|compromised|faded',
          style: 'solid|dashed'
        }
      ],
      labels: [
        { node: 'attacker', text: 'Label text' }
      ],
      attackerPosition: 'middle|top|bottom'
    }
    // ... more diagram actions (one per step)
  ],
  mitigations: [
    'First mitigation strategy',
    'Second mitigation strategy',
    // ... more mitigations
  ]
}
```

### Step 2: Test the Attack

1. Reload `attacks.html`
2. Select your new attack from the sidebar
3. Step through and verify animations
4. Adjust `diagramActions` as needed

### Attack Spec Reference

#### Top-Level Fields

- **id**: Unique identifier (string, kebab-case)
- **title**: Display name (string)
- **category**: Attack category (string)
- **severity**: `'critical'`, `'high'`, or `'medium'`
- **description**: Short summary (string)
- **steps**: Array of step objects
- **diagramActions**: Array of diagram action objects (must match steps.length)
- **mitigations**: Array of mitigation strings

#### Step Object

- **text**: Step description (string)
- **highlight**: Visual theme - `'normal'`, `'attack'`, or `'compromised'`

#### Diagram Action Object

- **step**: Step index (number, 0-based)
- **action**: Animation type
  - `'showFlow'`: Normal OAuth communication
  - `'highlightAttack'`: Highlight attack vector
  - `'showAttack'`: Show attacker action
  - `'showCompromised'`: Show compromised state
- **nodes**: Active nodes in this step (array of node IDs)
- **arrows**: Communication arrows (array of arrow objects)
- **labels** (optional): Status labels for nodes (array of label objects)
- **attackerPosition** (optional): `'middle'`, `'top'`, or `'bottom'`

#### Arrow Object

- **from**: Source node ID
- **to**: Target node ID
- **label**: Arrow label text (string)
- **color**: `'normal'` (blue), `'attack'` (red), `'compromised'` (purple), `'faded'` (gray)
- **style**: `'solid'` or `'dashed'`

#### Label Object

- **node**: Target node ID
- **text**: Label text (string)

#### Available Node IDs

- `'user'`: End user
- `'client'`: Client application
- `'authServer'`: Authorization server
- `'resourceServer'`: Resource server
- `'attacker'`: Malicious actor

## Architecture

### Component Structure

```
attacks.html (Alpine.js component)
    ├── Attack List (sidebar)
    ├── Diagram Visualization
    │   ├── Node positioning
    │   ├── Arrow rendering (SVG)
    │   └── Animation controller
    └── Attack Details
        ├── Step breakdown
        └── Mitigation guidance
```

### Animation Flow

1. User selects attack → `selectAttack()`
2. Controller resets diagram → `resetDiagram()`
3. User clicks "Next" → `nextStep()`
4. Controller applies step styling → `applyNodeStyling()`
5. Controller draws arrows → `drawArrows()`
6. Anime.js animates transitions → `animateStepTransition()`

### Styling System

- **Node States**: `.active`, `.attack`, `.compromised`, `.faded`, `.hidden`
- **Arrow Colors**: Defined in SVG `<marker>` elements
- **Animations**: CSS transitions + anime.js for complex motion

## Browser Compatibility

- **Chrome/Edge**: Full support (recommended)
- **Firefox**: Full support
- **Safari**: Full support
- **Mobile**: Responsive design works on tablets and phones

## Dependencies

- **Alpine.js 3.x**: Reactive framework (already in use)
- **Anime.js 3.2.1**: Lightweight animation library (~9KB gzipped)
- **Tailwind CSS**: Styling (via CDN, already in use)

## Security Considerations

This module is **educational only** and demonstrates:

- How vulnerabilities work
- Why they're dangerous
- How to prevent them

**Do not use these attack patterns maliciously.** They are provided solely for learning proper OAuth 2.0 security implementation.

## Future Extensions

To add more attack types:

1. **Implicit Flow Attacks**: Token leakage in URL fragments
2. **PKCE Bypass**: Attacks on weak PKCE implementations
3. **Clickjacking**: UI redressing attacks on consent screens
4. **Token Substitution**: Swapping tokens in multi-tenant scenarios

## Troubleshooting

### Arrows Not Rendering

- Check browser console for SVG errors
- Ensure node IDs match between HTML and attack spec
- Verify `arrow-canvas` SVG element exists

### Animations Not Playing

- Confirm anime.js loaded (check Network tab)
- Check for JavaScript errors in console
- Verify `animating` flag not stuck to `true`

### Diagram Layout Issues

- Nodes positioned via `positionNodes()` on load and resize
- Check container dimensions in DevTools
- Verify CSS transforms applied correctly

## Credits

- **Attack Scenarios**: Based on OWASP OAuth 2.0 Security Best Practices
- **Diagram Concept**: Inspired by OAuth.net flow diagrams
- **Animation Library**: [Anime.js](https://animejs.com/) by Julian Garnier

## License

Part of Credo project. See main project LICENSE file.
