// Attack Scenarios Specification
// Defines attack paths for OAuth 2.0 Authorization Code Flow

const ATTACK_SCENARIOS = [
  {
    id: 'code_interception',
    title: 'Authorization Code Interception',
    category: 'Code Flow Attacks',
    severity: 'high',
    description: 'Attacker intercepts the authorization code during redirect to steal user access',
    steps: [
      {
        text: 'User initiates OAuth flow and authenticates successfully',
        highlight: 'normal'
      },
      {
        text: 'Authorization server generates code and redirects to client',
        highlight: 'normal'
      },
      {
        text: 'Attacker intercepts redirect URL containing authorization code (via network sniffing, browser history, or referer headers)',
        highlight: 'attack'
      },
      {
        text: 'Attacker exchanges stolen code for access token before legitimate client',
        highlight: 'attack'
      },
      {
        text: 'Attacker gains unauthorized access to user resources',
        highlight: 'compromised'
      }
    ],
    diagramActions: [
      {
        step: 0,
        action: 'showFlow',
        nodes: ['user', 'authServer'],
        arrows: [{ from: 'user', to: 'authServer', label: 'Authenticate', color: 'normal' }]
      },
      {
        step: 1,
        action: 'showFlow',
        nodes: ['authServer', 'client'],
        arrows: [{ from: 'authServer', to: 'client', label: 'Redirect + Code', color: 'normal' }]
      },
      {
        step: 2,
        action: 'highlightAttack',
        nodes: ['attacker', 'authServer', 'client'],
        arrows: [
          { from: 'authServer', to: 'attacker', label: 'Code Intercepted', color: 'attack', style: 'dashed' },
          { from: 'authServer', to: 'client', label: 'Redirect + Code', color: 'faded' }
        ],
        attackerPosition: 'middle'
      },
      {
        step: 3,
        action: 'showAttack',
        nodes: ['attacker', 'authServer'],
        arrows: [{ from: 'attacker', to: 'authServer', label: 'Exchange Stolen Code', color: 'attack' }],
        labels: [{ node: 'attacker', text: 'Race Condition!' }]
      },
      {
        step: 4,
        action: 'showCompromised',
        nodes: ['attacker', 'resourceServer'],
        arrows: [{ from: 'attacker', to: 'resourceServer', label: 'Access with Token', color: 'compromised' }],
        labels: [{ node: 'resourceServer', text: 'Unauthorized Access' }]
      }
    ],
    mitigations: [
      'Use PKCE (Proof Key for Code Exchange) to bind code to client',
      'Enforce short code expiration (30-60 seconds)',
      'Use HTTPS only to prevent network interception',
      'Implement one-time code usage (reject replayed codes)'
    ]
  },
  {
    id: 'redirect_uri_manipulation',
    title: 'Redirect URI Manipulation',
    category: 'Code Flow Attacks',
    severity: 'critical',
    description: 'Attacker manipulates redirect_uri parameter to steal authorization code',
    steps: [
      {
        text: 'User clicks malicious link with crafted redirect_uri parameter',
        highlight: 'attack'
      },
      {
        text: 'User authenticates, unaware of malicious redirect',
        highlight: 'normal'
      },
      {
        text: 'Authorization server redirects to attacker-controlled URI with code',
        highlight: 'attack'
      },
      {
        text: 'Attacker captures authorization code from redirect',
        highlight: 'attack'
      },
      {
        text: 'Attacker exchanges code for access token and compromises account',
        highlight: 'compromised'
      }
    ],
    diagramActions: [
      {
        step: 0,
        action: 'showAttack',
        nodes: ['attacker', 'user'],
        arrows: [{ from: 'attacker', to: 'user', label: 'Phishing Link', color: 'attack', style: 'dashed' }],
        labels: [{ node: 'attacker', text: 'Crafted redirect_uri' }]
      },
      {
        step: 1,
        action: 'showFlow',
        nodes: ['user', 'authServer'],
        arrows: [{ from: 'user', to: 'authServer', label: 'Authenticate', color: 'normal' }]
      },
      {
        step: 2,
        action: 'highlightAttack',
        nodes: ['authServer', 'attacker'],
        arrows: [{ from: 'authServer', to: 'attacker', label: 'Redirect to Evil URI', color: 'attack' }],
        labels: [{ node: 'authServer', text: 'Misconfigured!' }]
      },
      {
        step: 3,
        action: 'showAttack',
        nodes: ['attacker'],
        labels: [{ node: 'attacker', text: 'Code Captured!' }]
      },
      {
        step: 4,
        action: 'showCompromised',
        nodes: ['attacker', 'authServer', 'resourceServer'],
        arrows: [
          { from: 'attacker', to: 'authServer', label: 'Exchange Code', color: 'attack' },
          { from: 'attacker', to: 'resourceServer', label: 'Access Resources', color: 'compromised' }
        ]
      }
    ],
    mitigations: [
      'Enforce exact redirect_uri matching (no wildcards)',
      'Pre-register all redirect URIs with authorization server',
      'Validate redirect_uri on token exchange',
      'Use https:// only for redirect URIs (reject http://)'
    ]
  },
  {
    id: 'token_leakage_storage',
    title: 'Token Leakage via Browser Storage',
    category: 'Token Security',
    severity: 'high',
    description: 'Access tokens exposed through insecure browser storage (localStorage/sessionStorage)',
    steps: [
      {
        text: 'Client successfully obtains access token via OAuth flow',
        highlight: 'normal'
      },
      {
        text: 'Client stores access token in localStorage or sessionStorage',
        highlight: 'attack'
      },
      {
        text: 'XSS vulnerability allows attacker to inject malicious JavaScript',
        highlight: 'attack'
      },
      {
        text: 'Attacker script reads token from browser storage',
        highlight: 'attack'
      },
      {
        text: 'Attacker exfiltrates token and accesses user resources',
        highlight: 'compromised'
      }
    ],
    diagramActions: [
      {
        step: 0,
        action: 'showFlow',
        nodes: ['client', 'authServer'],
        arrows: [{ from: 'authServer', to: 'client', label: 'Access Token', color: 'normal' }]
      },
      {
        step: 1,
        action: 'highlightAttack',
        nodes: ['client'],
        labels: [{ node: 'client', text: 'Token in localStorage' }]
      },
      {
        step: 2,
        action: 'showAttack',
        nodes: ['attacker', 'client'],
        arrows: [{ from: 'attacker', to: 'client', label: 'XSS Injection', color: 'attack', style: 'dashed' }],
        labels: [{ node: 'attacker', text: 'Malicious Script' }]
      },
      {
        step: 3,
        action: 'showAttack',
        nodes: ['client', 'attacker'],
        arrows: [{ from: 'client', to: 'attacker', label: 'Read Token', color: 'attack' }]
      },
      {
        step: 4,
        action: 'showCompromised',
        nodes: ['attacker', 'resourceServer'],
        arrows: [{ from: 'attacker', to: 'resourceServer', label: 'Access with Stolen Token', color: 'compromised' }]
      }
    ],
    mitigations: [
      'Store tokens in httpOnly, secure cookies (not accessible to JavaScript)',
      'Use short-lived access tokens with refresh token rotation',
      'Implement Content Security Policy (CSP) to prevent XSS',
      'Use Backend-for-Frontend (BFF) pattern to keep tokens server-side'
    ]
  },
  {
    id: 'token_leakage_logs',
    title: 'Token Leakage via Logs & Referrer Headers',
    category: 'Token Security',
    severity: 'medium',
    description: 'Access tokens leaked through application logs, URLs, or HTTP referer headers',
    steps: [
      {
        text: 'Client receives access token from authorization server',
        highlight: 'normal'
      },
      {
        text: 'Token accidentally included in URL parameters or query strings',
        highlight: 'attack'
      },
      {
        text: 'Token logged in server logs, analytics, or monitoring tools',
        highlight: 'attack'
      },
      {
        text: 'Token sent in Referer header when navigating to external site',
        highlight: 'attack'
      },
      {
        text: 'Attacker gains access via leaked logs or referrer data',
        highlight: 'compromised'
      }
    ],
    diagramActions: [
      {
        step: 0,
        action: 'showFlow',
        nodes: ['authServer', 'client'],
        arrows: [{ from: 'authServer', to: 'client', label: 'Token Response', color: 'normal' }]
      },
      {
        step: 1,
        action: 'highlightAttack',
        nodes: ['client'],
        labels: [{ node: 'client', text: 'Token in URL: ?token=...' }]
      },
      {
        step: 2,
        action: 'showAttack',
        nodes: ['client', 'attacker'],
        arrows: [{ from: 'client', to: 'attacker', label: 'Logged to Files', color: 'attack', style: 'dashed' }],
        labels: [{ node: 'attacker', text: 'Log Access' }]
      },
      {
        step: 3,
        action: 'showAttack',
        nodes: ['client', 'attacker'],
        arrows: [{ from: 'client', to: 'attacker', label: 'Referer Header', color: 'attack', style: 'dashed' }]
      },
      {
        step: 4,
        action: 'showCompromised',
        nodes: ['attacker', 'resourceServer'],
        arrows: [{ from: 'attacker', to: 'resourceServer', label: 'Use Leaked Token', color: 'compromised' }]
      }
    ],
    mitigations: [
      'Never pass tokens in URL parameters (use Authorization header)',
      'Sanitize logs to exclude tokens and sensitive data',
      'Use Referrer-Policy header to prevent token leakage',
      'Implement token hashing in logs if logging is necessary'
    ]
  },
  {
    id: 'scope_escalation',
    title: 'Scope Escalation Attack',
    category: 'Authorization',
    severity: 'medium',
    description: 'Attacker manipulates scope parameter to gain unauthorized permissions',
    steps: [
      {
        text: 'User initiates OAuth flow with limited scope (e.g., "read:profile")',
        highlight: 'normal'
      },
      {
        text: 'Attacker intercepts authorization request',
        highlight: 'attack'
      },
      {
        text: 'Attacker modifies scope to include elevated permissions (e.g., "write:profile delete:account")',
        highlight: 'attack'
      },
      {
        text: 'User unknowingly consents to escalated scopes',
        highlight: 'attack'
      },
      {
        text: 'Attacker gains access token with unauthorized permissions',
        highlight: 'compromised'
      }
    ],
    diagramActions: [
      {
        step: 0,
        action: 'showFlow',
        nodes: ['user', 'client'],
        arrows: [{ from: 'user', to: 'client', label: 'Request: scope=read', color: 'normal' }]
      },
      {
        step: 1,
        action: 'showAttack',
        nodes: ['attacker', 'client'],
        arrows: [{ from: 'attacker', to: 'client', label: 'Intercept', color: 'attack', style: 'dashed' }],
        attackerPosition: 'middle'
      },
      {
        step: 2,
        action: 'highlightAttack',
        nodes: ['attacker', 'authServer'],
        arrows: [{ from: 'attacker', to: 'authServer', label: 'Modified: scope=read+write+delete', color: 'attack' }],
        labels: [{ node: 'attacker', text: 'Scope Injection!' }]
      },
      {
        step: 3,
        action: 'showFlow',
        nodes: ['user', 'authServer'],
        arrows: [{ from: 'authServer', to: 'user', label: 'Consent Screen (Elevated)', color: 'normal' }]
      },
      {
        step: 4,
        action: 'showCompromised',
        nodes: ['attacker', 'resourceServer'],
        arrows: [{ from: 'attacker', to: 'resourceServer', label: 'Access with Elevated Scopes', color: 'compromised' }],
        labels: [{ node: 'resourceServer', text: 'Unauthorized Actions' }]
      }
    ],
    mitigations: [
      'Display clear consent screens showing exact permissions requested',
      'Validate requested scopes against client registration',
      'Implement scope downgrade if user denies some permissions',
      'Log scope changes for security monitoring'
    ]
  },
  {
    id: 'csrf_attack',
    title: 'Cross-Site Request Forgery (CSRF) on Callback',
    category: 'Code Flow Attacks',
    severity: 'high',
    description: 'Attacker forces victim to complete OAuth flow with attacker\'s authorization code',
    steps: [
      {
        text: 'Attacker initiates OAuth flow and obtains authorization code',
        highlight: 'attack'
      },
      {
        text: 'Attacker crafts malicious page with auto-submitting form to client callback',
        highlight: 'attack'
      },
      {
        text: 'Victim visits attacker\'s page while logged into client application',
        highlight: 'attack'
      },
      {
        text: 'Client exchanges attacker\'s code for token and links to victim\'s session',
        highlight: 'attack'
      },
      {
        text: 'Victim unknowingly uses attacker\'s account, exposing their data to attacker',
        highlight: 'compromised'
      }
    ],
    diagramActions: [
      {
        step: 0,
        action: 'showAttack',
        nodes: ['attacker', 'authServer'],
        arrows: [{ from: 'attacker', to: 'authServer', label: 'Get Auth Code', color: 'attack' }]
      },
      {
        step: 1,
        action: 'showAttack',
        nodes: ['attacker'],
        labels: [{ node: 'attacker', text: 'Craft CSRF Page' }]
      },
      {
        step: 2,
        action: 'showAttack',
        nodes: ['attacker', 'user', 'client'],
        arrows: [
          { from: 'attacker', to: 'user', label: 'Phishing Link', color: 'attack', style: 'dashed' },
          { from: 'user', to: 'client', label: 'Auto-Submit Form', color: 'attack' }
        ]
      },
      {
        step: 3,
        action: 'highlightAttack',
        nodes: ['client', 'authServer'],
        arrows: [{ from: 'client', to: 'authServer', label: 'Exchange Attacker Code', color: 'attack' }],
        labels: [{ node: 'client', text: 'No CSRF Protection!' }]
      },
      {
        step: 4,
        action: 'showCompromised',
        nodes: ['user', 'client', 'attacker'],
        arrows: [{ from: 'user', to: 'client', label: 'User Data', color: 'compromised' }, { from: 'client', to: 'attacker', label: 'Data Leaked', color: 'compromised', style: 'dashed' }],
        labels: [{ node: 'attacker', text: 'Account Linking Attack' }]
      }
    ],
    mitigations: [
      'Always use and validate state parameter (cryptographically random)',
      'Implement nonce parameter for OIDC flows',
      'Use SameSite cookie attribute for session cookies',
      'Require user confirmation before account linking'
    ]
  }
];

// Export for use in attacks.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ATTACK_SCENARIOS;
}
