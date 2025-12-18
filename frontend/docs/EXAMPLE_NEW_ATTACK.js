// EXAMPLE: How to Add a New Attack Scenario
// Copy this template to attack-scenarios.js and customize

const EXAMPLE_NEW_ATTACK = {
  // Unique identifier (kebab-case, lowercase)
  id: 'state_parameter_missing',

  // Display name shown in UI
  title: 'Missing State Parameter (CSRF)',

  // Category for grouping
  category: 'Code Flow Attacks',

  // Severity: 'critical', 'high', or 'medium'
  severity: 'high',

  // Brief description (1-2 sentences)
  description: 'OAuth flow without state parameter allows CSRF attacks where attacker can link their account to victim\'s session',

  // Step-by-step breakdown (3-6 steps recommended)
  steps: [
    {
      text: 'Client initiates OAuth flow without state parameter',
      highlight: 'normal' // 'normal', 'attack', or 'compromised'
    },
    {
      text: 'Attacker starts their own OAuth flow and captures authorization code',
      highlight: 'attack'
    },
    {
      text: 'Attacker tricks victim into completing OAuth flow with attacker\'s code',
      highlight: 'attack'
    },
    {
      text: 'Victim\'s session is linked to attacker\'s account',
      highlight: 'attack'
    },
    {
      text: 'Attacker gains access to victim\'s data through linked account',
      highlight: 'compromised'
    }
  ],

  // Diagram actions (MUST match number of steps)
  diagramActions: [
    // STEP 0: Show normal flow without state
    {
      step: 0,
      action: 'showFlow', // 'showFlow', 'highlightAttack', 'showAttack', 'showCompromised'
      nodes: ['user', 'client', 'authServer'],
      arrows: [
        {
          from: 'user',
          to: 'client',
          label: 'Click Login',
          color: 'normal', // 'normal', 'attack', 'compromised', 'faded'
          style: 'solid'   // 'solid' or 'dashed'
        },
        {
          from: 'client',
          to: 'authServer',
          label: 'Auth Request (NO state)',
          color: 'normal'
        }
      ],
      labels: [
        { node: 'client', text: 'No CSRF Protection!' }
      ]
    },

    // STEP 1: Attacker gets their own code
    {
      step: 1,
      action: 'showAttack',
      nodes: ['attacker', 'authServer'],
      arrows: [
        {
          from: 'attacker',
          to: 'authServer',
          label: 'Start OAuth',
          color: 'attack'
        },
        {
          from: 'authServer',
          to: 'attacker',
          label: 'Auth Code',
          color: 'attack'
        }
      ],
      labels: [
        { node: 'attacker', text: 'Capture Code' }
      ]
    },

    // STEP 2: Attacker sends malicious link to victim
    {
      step: 2,
      action: 'highlightAttack',
      nodes: ['attacker', 'user', 'client'],
      arrows: [
        {
          from: 'attacker',
          to: 'user',
          label: 'Malicious Link',
          color: 'attack',
          style: 'dashed'
        },
        {
          from: 'user',
          to: 'client',
          label: 'Complete Flow',
          color: 'attack'
        }
      ],
      attackerPosition: 'middle' // 'middle', 'top', 'bottom' (optional)
    },

    // STEP 3: Victim's session linked to attacker account
    {
      step: 3,
      action: 'showAttack',
      nodes: ['client', 'user', 'attacker'],
      arrows: [
        {
          from: 'client',
          to: 'user',
          label: 'Session Created',
          color: 'attack'
        },
        {
          from: 'user',
          to: 'attacker',
          label: 'Linked!',
          color: 'attack',
          style: 'dashed'
        }
      ],
      labels: [
        { node: 'client', text: 'Attacker Account Linked' }
      ]
    },

    // STEP 4: Compromised - attacker accesses data
    {
      step: 4,
      action: 'showCompromised',
      nodes: ['attacker', 'client', 'resourceServer'],
      arrows: [
        {
          from: 'attacker',
          to: 'client',
          label: 'Login as Victim',
          color: 'compromised'
        },
        {
          from: 'client',
          to: 'resourceServer',
          label: 'Access Data',
          color: 'compromised'
        }
      ],
      labels: [
        { node: 'resourceServer', text: 'Data Exposed' }
      ]
    }
  ],

  // Mitigation strategies (3-5 recommended)
  mitigations: [
    'Always include state parameter with cryptographically random value (minimum 128 bits)',
    'Validate state parameter on callback - reject if missing or mismatched',
    'Use framework-provided CSRF protection (most OAuth libraries handle this)',
    'Implement SameSite=Lax cookies for additional CSRF defense',
    'Log and alert on state parameter validation failures'
  ]
};

// ==============================================================================
// QUICK REFERENCE: Diagram Action Types
// ==============================================================================

// 'showFlow' - Normal OAuth communication (blue)
// Best for: Initial setup, successful operations
const SHOW_FLOW_EXAMPLE = {
  step: 0,
  action: 'showFlow',
  nodes: ['user', 'client', 'authServer'],
  arrows: [{ from: 'user', to: 'authServer', label: 'Login', color: 'normal' }]
};

// 'highlightAttack' - Emphasize attack vector (red)
// Best for: Man-in-the-middle, interception points
const HIGHLIGHT_ATTACK_EXAMPLE = {
  step: 1,
  action: 'highlightAttack',
  nodes: ['attacker', 'user', 'authServer'],
  arrows: [
    { from: 'user', to: 'authServer', label: 'Request', color: 'faded' },
    { from: 'user', to: 'attacker', label: 'Intercepted', color: 'attack', style: 'dashed' }
  ],
  attackerPosition: 'middle' // Place attacker between two nodes
};

// 'showAttack' - Pure attack action (red)
// Best for: Attacker-initiated actions
const SHOW_ATTACK_EXAMPLE = {
  step: 2,
  action: 'showAttack',
  nodes: ['attacker', 'authServer'],
  arrows: [{ from: 'attacker', to: 'authServer', label: 'Exploit', color: 'attack' }],
  labels: [{ node: 'attacker', text: 'Malicious Request' }]
};

// 'showCompromised' - Final compromised state (purple)
// Best for: Final step showing data breach or unauthorized access
const SHOW_COMPROMISED_EXAMPLE = {
  step: 3,
  action: 'showCompromised',
  nodes: ['attacker', 'resourceServer'],
  arrows: [{ from: 'attacker', to: 'resourceServer', label: 'Unauthorized Access', color: 'compromised' }],
  labels: [{ node: 'resourceServer', text: 'Data Stolen' }]
};

// ==============================================================================
// AVAILABLE NODES
// ==============================================================================

// 'user' - End user (positioned left side, blue gradient)
// 'client' - Client application (positioned right side, purple gradient)
// 'authServer' - Authorization server (positioned top, yellow gradient)
// 'resourceServer' - Resource server (positioned bottom, green gradient)
// 'attacker' - Malicious actor (positioned dynamically, red gradient)

// ==============================================================================
// ARROW COLORS
// ==============================================================================

// 'normal' - Blue (#3b82f6) - Standard OAuth flow
// 'attack' - Red (#dc2626) - Attack vectors
// 'compromised' - Purple (#7c3aed) - Compromised/unauthorized access
// 'faded' - Gray (#9ca3af) - Inactive/background communication

// ==============================================================================
// ARROW STYLES
// ==============================================================================

// 'solid' - Solid line (default)
// 'dashed' - Dashed line (use for interception, injection, phishing)

// ==============================================================================
// STEP HIGHLIGHTS
// ==============================================================================

// 'normal' - Blue highlight in step list
// 'attack' - Red highlight in step list
// 'compromised' - Purple highlight in step list

// ==============================================================================
// TESTING YOUR NEW ATTACK
// ==============================================================================

// 1. Add your attack object to ATTACK_SCENARIOS array in attack-scenarios.js
// 2. Reload attacks.html in browser
// 3. Select your attack from sidebar
// 4. Click "Next" through all steps
// 5. Verify:
//    - All nodes appear/disappear correctly
//    - Arrows draw between correct nodes
//    - Labels show on correct nodes
//    - Colors match severity/action type
//    - Animations are smooth
//    - Mitigations display at bottom

// ==============================================================================
// COMMON PATTERNS
// ==============================================================================

// Pattern 1: Man-in-the-Middle
const MITM_PATTERN = {
  step: 1,
  action: 'highlightAttack',
  nodes: ['user', 'attacker', 'authServer'],
  arrows: [
    { from: 'user', to: 'attacker', label: 'Intercepted', color: 'attack' },
    { from: 'attacker', to: 'authServer', label: 'Forwarded', color: 'attack', style: 'dashed' }
  ],
  attackerPosition: 'middle'
};

// Pattern 2: Phishing
const PHISHING_PATTERN = {
  step: 1,
  action: 'showAttack',
  nodes: ['attacker', 'user'],
  arrows: [
    { from: 'attacker', to: 'user', label: 'Fake Email', color: 'attack', style: 'dashed' }
  ],
  labels: [{ node: 'attacker', text: 'Spoofed Domain' }]
};

// Pattern 3: Token Theft
const TOKEN_THEFT_PATTERN = {
  step: 2,
  action: 'showAttack',
  nodes: ['client', 'attacker'],
  arrows: [
    { from: 'client', to: 'attacker', label: 'Token Leaked', color: 'attack', style: 'dashed' }
  ],
  labels: [{ node: 'client', text: 'Insecure Storage' }]
};

// Pattern 4: Unauthorized Access (Final Step)
const UNAUTHORIZED_ACCESS_PATTERN = {
  step: 4,
  action: 'showCompromised',
  nodes: ['attacker', 'resourceServer'],
  arrows: [
    { from: 'attacker', to: 'resourceServer', label: 'Access Data', color: 'compromised' }
  ],
  labels: [{ node: 'resourceServer', text: 'Breach!' }]
};
