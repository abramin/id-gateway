/**
 * Attack Definitions
 * Comprehensive specifications for OAuth 2.0 attack scenarios
 * Used by all three modules
 */

const ATTACK_DEFINITIONS = [
  {
    id: 'code_interception',
    title: 'Authorization Code Interception',
    category: 'Code Flow Attacks',
    severity: 'high',
    description: 'Attacker intercepts the authorization code during redirect and exchanges it for tokens before the legitimate client.',
    shortDescription: 'Steal auth code, get tokens',

    // Which security controls block this attack
    blockedBy: ['requirePkce'],
    partiallyBlockedBy: ['httpsOnlyRedirects'],

    // Technical details for Request Forge
    technicalDetails: {
      attackVector: 'Network interception, browser history, referrer headers',
      prerequisites: ['Access to network traffic OR browser history', 'PKCE not required'],
      impact: 'Full account takeover - attacker gets access and refresh tokens'
    },

    // Steps for visualization and Dual Perspective
    steps: [
      {
        id: 'user_auth',
        title: 'User Authenticates',
        description: 'User initiates OAuth flow and authenticates with the authorization server.',
        perspective: 'normal',
        diagramNodes: ['user', 'authServer'],
        diagramArrow: { from: 'user', to: 'authServer', label: 'Authenticate' }
      },
      {
        id: 'code_issued',
        title: 'Code Issued',
        description: 'Authorization server generates code and redirects to client via user\'s browser.',
        perspective: 'normal',
        diagramNodes: ['authServer', 'user', 'client'],
        diagramArrow: { from: 'authServer', to: 'client', label: 'Redirect + Code', through: 'user' }
      },
      {
        id: 'intercept',
        title: 'Attacker Intercepts Code',
        description: 'Attacker captures the authorization code from the redirect URL through network sniffing, browser history, or referrer headers.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'user'],
        diagramArrow: { from: 'user', to: 'attacker', label: 'Code Intercepted', style: 'dashed' }
      },
      {
        id: 'exchange',
        title: 'Attacker Exchanges Code',
        description: 'Attacker races to exchange the stolen code for tokens before the legitimate client.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'authServer'],
        diagramArrow: { from: 'attacker', to: 'authServer', label: 'Exchange Code' }
      },
      {
        id: 'compromise',
        title: 'Account Compromised',
        description: 'Attacker receives tokens and gains full access to user\'s resources.',
        perspective: 'compromised',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: { from: 'attacker', to: 'resourceServer', label: 'Access Resources' }
      }
    ],

    // Mitigations
    mitigations: [
      {
        control: 'requirePkce',
        title: 'Enable PKCE',
        description: 'PKCE binds the authorization code to the client that initiated the request. Without the code_verifier, the attacker cannot exchange the stolen code.',
        effectiveness: 'complete'
      },
      {
        control: 'httpsOnlyRedirects',
        title: 'HTTPS-Only Redirects',
        description: 'Ensures codes are transmitted over encrypted connections, preventing network-level interception.',
        effectiveness: 'partial'
      },
      {
        control: null,
        title: 'Short Code Expiration',
        description: 'Reduce the time window for code interception by using short-lived authorization codes (30-60 seconds).',
        effectiveness: 'partial'
      }
    ],

    // For Dual Perspective story mode
    story: {
      attacker: {
        intro: "You've discovered a web application that uses OAuth 2.0 for authentication. Through reconnaissance, you notice the authorization requests don't include PKCE parameters...",
        goal: "Intercept an authorization code and use it to gain access to a victim's account."
      },
      defender: {
        intro: "You're the security engineer responsible for your company's OAuth implementation. A security audit has flagged potential vulnerabilities in how authorization codes are handled...",
        goal: "Configure the authorization server to prevent code interception attacks."
      }
    }
  },

  {
    id: 'redirect_manipulation',
    title: 'Redirect URI Manipulation',
    category: 'Code Flow Attacks',
    severity: 'critical',
    description: 'Attacker manipulates the redirect_uri parameter to redirect authorization codes to an attacker-controlled endpoint.',
    shortDescription: 'Hijack redirect to steal code',

    blockedBy: ['strictRedirectUri'],
    partiallyBlockedBy: ['allowWildcardRedirects'],

    technicalDetails: {
      attackVector: 'Phishing, URL manipulation',
      prerequisites: ['Loose redirect URI validation', 'Victim clicks malicious link'],
      impact: 'Authorization code sent directly to attacker'
    },

    steps: [
      {
        id: 'craft_link',
        title: 'Attacker Crafts Malicious Link',
        description: 'Attacker creates an authorization URL with redirect_uri pointing to their server.',
        perspective: 'attack',
        diagramNodes: ['attacker'],
        diagramArrow: null
      },
      {
        id: 'phishing',
        title: 'Victim Clicks Link',
        description: 'User clicks the malicious link, often through phishing or a compromised website.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'user'],
        diagramArrow: { from: 'attacker', to: 'user', label: 'Phishing Link', style: 'dashed' }
      },
      {
        id: 'user_auth',
        title: 'User Authenticates',
        description: 'User authenticates normally, unaware that the redirect will go to the attacker.',
        perspective: 'normal',
        diagramNodes: ['user', 'authServer'],
        diagramArrow: { from: 'user', to: 'authServer', label: 'Authenticate' }
      },
      {
        id: 'redirect_to_attacker',
        title: 'Code Redirected to Attacker',
        description: 'Authorization server redirects the code to the attacker\'s malicious URI.',
        perspective: 'attack',
        diagramNodes: ['authServer', 'attacker'],
        diagramArrow: { from: 'authServer', to: 'attacker', label: 'Redirect + Code' }
      },
      {
        id: 'compromise',
        title: 'Attacker Exchanges Code',
        description: 'Attacker exchanges the code for tokens and gains access.',
        perspective: 'compromised',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: { from: 'attacker', to: 'resourceServer', label: 'Access Resources' }
      }
    ],

    mitigations: [
      {
        control: 'strictRedirectUri',
        title: 'Exact Redirect URI Matching',
        description: 'Only allow pre-registered redirect URIs with exact string matching. No pattern matching or wildcards.',
        effectiveness: 'complete'
      },
      {
        control: 'allowWildcardRedirects',
        title: 'Disable Wildcards',
        description: 'Never allow wildcard patterns in redirect URI validation.',
        effectiveness: 'complete'
      },
      {
        control: 'httpsOnlyRedirects',
        title: 'HTTPS-Only',
        description: 'Require all redirect URIs to use HTTPS.',
        effectiveness: 'partial'
      }
    ],

    story: {
      attacker: {
        intro: "You've found an OAuth client that has loose redirect URI validation. The authorization server seems to accept any URI under the client's domain, or even completely different domains...",
        goal: "Craft a malicious authorization URL that will send the victim's code to your server."
      },
      defender: {
        intro: "Your security team has received reports of phishing attacks targeting your OAuth flow. Attackers seem to be able to redirect authorization codes to their own servers...",
        goal: "Tighten redirect URI validation to prevent open redirect attacks."
      }
    }
  },

  {
    id: 'token_replay',
    title: 'Token Replay Across Services',
    category: 'Token Security',
    severity: 'high',
    description: 'Attacker steals an access token and replays it against a different resource server that doesn\'t validate the audience claim.',
    shortDescription: 'Use token on wrong service',

    blockedBy: ['validateAudience'],
    partiallyBlockedBy: ['shortTokenLifetime'],

    technicalDetails: {
      attackVector: 'Token theft, audience confusion',
      prerequisites: ['Access to valid token', 'Resource server doesn\'t validate audience'],
      impact: 'Unauthorized access to different service using legitimate token'
    },

    steps: [
      {
        id: 'obtain_token',
        title: 'Attacker Obtains Token',
        description: 'Attacker obtains a valid access token through legitimate means or theft.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'authServer'],
        diagramArrow: { from: 'authServer', to: 'attacker', label: 'Access Token' }
      },
      {
        id: 'identify_target',
        title: 'Identify Vulnerable Service',
        description: 'Attacker identifies another resource server that uses the same authorization server.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: null
      },
      {
        id: 'replay',
        title: 'Replay Token',
        description: 'Attacker sends the token to the vulnerable resource server.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: { from: 'attacker', to: 'resourceServer', label: 'Replay Token' }
      },
      {
        id: 'no_validation',
        title: 'Audience Not Validated',
        description: 'Resource server accepts the token without checking the audience claim.',
        perspective: 'attack',
        diagramNodes: ['resourceServer'],
        diagramArrow: null
      },
      {
        id: 'compromise',
        title: 'Unauthorized Access',
        description: 'Attacker gains access to resources they shouldn\'t have access to.',
        perspective: 'compromised',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: { from: 'attacker', to: 'resourceServer', label: 'Access Granted' }
      }
    ],

    mitigations: [
      {
        control: 'validateAudience',
        title: 'Validate Audience Claim',
        description: 'Every resource server must validate that the token\'s audience claim matches its own identifier.',
        effectiveness: 'complete'
      },
      {
        control: 'shortTokenLifetime',
        title: 'Short Token Lifetime',
        description: 'Reduce the window of opportunity by using short-lived access tokens.',
        effectiveness: 'partial'
      }
    ],

    story: {
      attacker: {
        intro: "You've obtained a valid access token for one service. You notice the organization runs multiple services that all use the same authorization server...",
        goal: "Use the token to access a different service than it was intended for."
      },
      defender: {
        intro: "Your organization runs multiple microservices, all using the central OAuth server. You need to ensure tokens can't be used across service boundaries...",
        goal: "Configure resource servers to properly validate token audience claims."
      }
    }
  },

  {
    id: 'csrf_callback',
    title: 'CSRF on OAuth Callback',
    category: 'Code Flow Attacks',
    severity: 'high',
    description: 'Attacker forces victim to complete an OAuth flow using the attacker\'s authorization code, linking the victim\'s session to the attacker\'s account.',
    shortDescription: 'Force victim to use attacker\'s code',

    blockedBy: ['requireStateParam'],
    partiallyBlockedBy: [],

    technicalDetails: {
      attackVector: 'Cross-site request forgery',
      prerequisites: ['No state parameter validation', 'Victim logged into client app'],
      impact: 'Session fixation, account linking to attacker\'s identity'
    },

    steps: [
      {
        id: 'attacker_auth',
        title: 'Attacker Gets Code',
        description: 'Attacker initiates OAuth flow and obtains their own authorization code.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'authServer'],
        diagramArrow: { from: 'authServer', to: 'attacker', label: 'Attacker\'s Code' }
      },
      {
        id: 'craft_csrf',
        title: 'Craft CSRF Page',
        description: 'Attacker creates a page that auto-submits the callback with their code.',
        perspective: 'attack',
        diagramNodes: ['attacker'],
        diagramArrow: null
      },
      {
        id: 'victim_visits',
        title: 'Victim Visits Page',
        description: 'Victim visits the attacker\'s page while logged into the client application.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'user'],
        diagramArrow: { from: 'attacker', to: 'user', label: 'CSRF Page' }
      },
      {
        id: 'callback_triggered',
        title: 'Callback Triggered',
        description: 'Victim\'s browser submits the callback with attacker\'s code.',
        perspective: 'attack',
        diagramNodes: ['user', 'client'],
        diagramArrow: { from: 'user', to: 'client', label: 'Callback + Attacker Code' }
      },
      {
        id: 'account_linked',
        title: 'Account Linked',
        description: 'Victim\'s session is now linked to attacker\'s OAuth account.',
        perspective: 'compromised',
        diagramNodes: ['user', 'client', 'attacker'],
        diagramArrow: { from: 'client', to: 'attacker', label: 'Victim\'s Data', style: 'dashed' }
      }
    ],

    mitigations: [
      {
        control: 'requireStateParam',
        title: 'Require State Parameter',
        description: 'Generate a cryptographically random state value for each authorization request and validate it on callback.',
        effectiveness: 'complete'
      },
      {
        control: null,
        title: 'SameSite Cookies',
        description: 'Use SameSite=Strict or SameSite=Lax for session cookies.',
        effectiveness: 'partial'
      }
    ],

    story: {
      attacker: {
        intro: "You want to gain access to a victim's data on a client application. Instead of stealing their credentials, you'll trick them into linking their account to your OAuth identity...",
        goal: "Create a CSRF attack that links the victim's session to your OAuth account."
      },
      defender: {
        intro: "Users are reporting strange behavior - their accounts seem to be connected to unknown OAuth identities. Investigation reveals a CSRF vulnerability in the OAuth callback...",
        goal: "Implement state parameter validation to prevent CSRF attacks."
      }
    }
  },

  {
    id: 'scope_escalation',
    title: 'Scope Escalation',
    category: 'Authorization',
    severity: 'medium',
    description: 'Attacker manipulates the scope parameter to request more permissions than the user or client should have.',
    shortDescription: 'Request elevated permissions',

    blockedBy: [],
    partiallyBlockedBy: ['requirePkce'],

    technicalDetails: {
      attackVector: 'Parameter manipulation, confused deputy',
      prerequisites: ['Ability to modify authorization request', 'Lax scope validation'],
      impact: 'Access to resources beyond intended permissions'
    },

    steps: [
      {
        id: 'observe_flow',
        title: 'Observe Normal Flow',
        description: 'Attacker observes the normal OAuth flow and identifies requested scopes.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'client'],
        diagramArrow: { from: 'attacker', to: 'client', label: 'Observe', style: 'dashed' }
      },
      {
        id: 'modify_request',
        title: 'Modify Scope Request',
        description: 'Attacker intercepts or crafts a request with elevated scopes.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'authServer'],
        diagramArrow: { from: 'attacker', to: 'authServer', label: 'scope=admin:all' }
      },
      {
        id: 'user_consent',
        title: 'User Consents',
        description: 'User may unknowingly consent to elevated permissions if consent screen is unclear.',
        perspective: 'attack',
        diagramNodes: ['user', 'authServer'],
        diagramArrow: { from: 'user', to: 'authServer', label: 'Approve' }
      },
      {
        id: 'elevated_token',
        title: 'Elevated Token Issued',
        description: 'Authorization server issues a token with elevated scopes.',
        perspective: 'attack',
        diagramNodes: ['authServer', 'attacker'],
        diagramArrow: { from: 'authServer', to: 'attacker', label: 'Token + Elevated Scopes' }
      },
      {
        id: 'abuse_access',
        title: 'Abuse Elevated Access',
        description: 'Attacker uses the token to perform actions beyond intended permissions.',
        perspective: 'compromised',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: { from: 'attacker', to: 'resourceServer', label: 'Admin Actions' }
      }
    ],

    mitigations: [
      {
        control: null,
        title: 'Clear Consent Screens',
        description: 'Display explicit, easy-to-understand consent screens showing exactly what permissions are being requested.',
        effectiveness: 'partial'
      },
      {
        control: null,
        title: 'Scope Validation',
        description: 'Validate requested scopes against what the client is allowed to request.',
        effectiveness: 'complete'
      },
      {
        control: null,
        title: 'Audit Logging',
        description: 'Log all scope requests and grants for security monitoring.',
        effectiveness: 'detection'
      }
    ],

    story: {
      attacker: {
        intro: "You've gained access to a low-privilege OAuth token but want more access. You notice the authorization server might accept scope parameters it shouldn't...",
        goal: "Escalate your access by manipulating scope parameters."
      },
      defender: {
        intro: "Security monitoring has detected unusual scope requests - some clients are requesting admin-level permissions they shouldn't need...",
        goal: "Implement proper scope validation and monitoring."
      }
    }
  },

  {
    id: 'token_storage_xss',
    title: 'Token Theft via XSS',
    category: 'Token Security',
    severity: 'high',
    description: 'Attacker exploits XSS vulnerability to steal access tokens from browser storage.',
    shortDescription: 'Steal tokens via JavaScript',

    blockedBy: [],
    partiallyBlockedBy: ['shortTokenLifetime'],

    technicalDetails: {
      attackVector: 'Cross-site scripting (XSS)',
      prerequisites: ['XSS vulnerability in client app', 'Tokens stored in accessible storage'],
      impact: 'Complete token theft, account takeover'
    },

    steps: [
      {
        id: 'find_xss',
        title: 'Find XSS Vulnerability',
        description: 'Attacker discovers XSS vulnerability in the client application.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'client'],
        diagramArrow: { from: 'attacker', to: 'client', label: 'Find XSS', style: 'dashed' }
      },
      {
        id: 'inject_script',
        title: 'Inject Malicious Script',
        description: 'Attacker injects JavaScript that reads tokens from localStorage/sessionStorage.',
        perspective: 'attack',
        diagramNodes: ['attacker', 'client'],
        diagramArrow: { from: 'attacker', to: 'client', label: 'XSS Payload' }
      },
      {
        id: 'victim_visits',
        title: 'Victim Triggers XSS',
        description: 'Victim visits the page containing the XSS payload.',
        perspective: 'attack',
        diagramNodes: ['user', 'client'],
        diagramArrow: { from: 'user', to: 'client', label: 'Load Page' }
      },
      {
        id: 'exfiltrate',
        title: 'Exfiltrate Token',
        description: 'Malicious script reads token and sends it to attacker\'s server.',
        perspective: 'attack',
        diagramNodes: ['client', 'attacker'],
        diagramArrow: { from: 'client', to: 'attacker', label: 'Stolen Token' }
      },
      {
        id: 'compromise',
        title: 'Account Takeover',
        description: 'Attacker uses stolen token to access victim\'s resources.',
        perspective: 'compromised',
        diagramNodes: ['attacker', 'resourceServer'],
        diagramArrow: { from: 'attacker', to: 'resourceServer', label: 'Access Resources' }
      }
    ],

    mitigations: [
      {
        control: null,
        title: 'HttpOnly Cookies',
        description: 'Store tokens in httpOnly cookies inaccessible to JavaScript.',
        effectiveness: 'complete'
      },
      {
        control: null,
        title: 'Content Security Policy',
        description: 'Implement strict CSP to prevent XSS attacks.',
        effectiveness: 'partial'
      },
      {
        control: 'shortTokenLifetime',
        title: 'Short Token Lifetime',
        description: 'Limit the damage window by using short-lived tokens.',
        effectiveness: 'partial'
      },
      {
        control: null,
        title: 'Backend for Frontend',
        description: 'Use BFF pattern to keep tokens on the server side.',
        effectiveness: 'complete'
      }
    ],

    story: {
      attacker: {
        intro: "You've found an XSS vulnerability in a popular web application. You know they store OAuth tokens in localStorage...",
        goal: "Exploit the XSS to steal tokens and gain access to user accounts."
      },
      defender: {
        intro: "A security researcher has reported XSS vulnerabilities in your application. You need to protect OAuth tokens from being stolen...",
        goal: "Implement secure token storage that's resilient to XSS attacks."
      }
    }
  }
];

// Helper function to get attack by ID
function getAttackById(id) {
  return ATTACK_DEFINITIONS.find(a => a.id === id);
}

// Helper function to get attacks blocked by a specific control
function getAttacksBlockedBy(control) {
  return ATTACK_DEFINITIONS.filter(a =>
    a.blockedBy.includes(control) || a.partiallyBlockedBy.includes(control)
  );
}

// Helper function to get attack severity class
function getSeverityClass(severity) {
  const classes = {
    critical: 'badge-error',
    high: 'badge-warning',
    medium: 'badge-info',
    low: 'badge-neutral'
  };
  return classes[severity] || 'badge-neutral';
}

// Export for use in modules
if (typeof window !== 'undefined') {
  window.ATTACK_DEFINITIONS = ATTACK_DEFINITIONS;
  window.getAttackById = getAttackById;
  window.getAttacksBlockedBy = getAttacksBlockedBy;
  window.getSeverityClass = getSeverityClass;
}
