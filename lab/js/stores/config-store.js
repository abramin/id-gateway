/**
 * Security Configuration Store
 * Central store for security control states, persisted to localStorage
 */

document.addEventListener('alpine:init', () => {
  const STORAGE_KEY = 'attack-lab-config';

  // Load saved config or use defaults
  const loadConfig = () => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.warn('Failed to load config from localStorage:', e);
    }
    return null;
  };

  const savedConfig = loadConfig();

  Alpine.store('config', {
    // PKCE Configuration
    requirePkce: savedConfig?.requirePkce ?? true,
    pkceMethod: savedConfig?.pkceMethod ?? 'S256',

    // Redirect URI Validation
    strictRedirectUri: savedConfig?.strictRedirectUri ?? true,
    allowWildcardRedirects: savedConfig?.allowWildcardRedirects ?? false,
    httpsOnlyRedirects: savedConfig?.httpsOnlyRedirects ?? true,

    // Token Security
    validateAudience: savedConfig?.validateAudience ?? true,
    shortTokenLifetime: savedConfig?.shortTokenLifetime ?? true,
    tokenLifetimeMinutes: savedConfig?.tokenLifetimeMinutes ?? 15,

    // State/CSRF Protection
    requireStateParam: savedConfig?.requireStateParam ?? true,

    // Advanced Options
    enableRefreshTokenRotation: savedConfig?.enableRefreshTokenRotation ?? true,
    bindTokenToDevice: savedConfig?.bindTokenToDevice ?? false,
    requireClientSecret: savedConfig?.requireClientSecret ?? false,

    // Persist to localStorage
    save() {
      try {
        const data = {
          requirePkce: this.requirePkce,
          pkceMethod: this.pkceMethod,
          strictRedirectUri: this.strictRedirectUri,
          allowWildcardRedirects: this.allowWildcardRedirects,
          httpsOnlyRedirects: this.httpsOnlyRedirects,
          validateAudience: this.validateAudience,
          shortTokenLifetime: this.shortTokenLifetime,
          tokenLifetimeMinutes: this.tokenLifetimeMinutes,
          requireStateParam: this.requireStateParam,
          enableRefreshTokenRotation: this.enableRefreshTokenRotation,
          bindTokenToDevice: this.bindTokenToDevice,
          requireClientSecret: this.requireClientSecret
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
      } catch (e) {
        console.warn('Failed to save config to localStorage:', e);
      }
    },

    // Computed: Security score (0-100)
    get securityScore() {
      let score = 0;
      if (this.requirePkce) score += 20;
      if (this.strictRedirectUri) score += 15;
      if (!this.allowWildcardRedirects) score += 5;
      if (this.httpsOnlyRedirects) score += 10;
      if (this.validateAudience) score += 20;
      if (this.shortTokenLifetime) score += 10;
      if (this.requireStateParam) score += 10;
      if (this.enableRefreshTokenRotation) score += 5;
      if (this.bindTokenToDevice) score += 5;
      return Math.min(100, score);
    },

    // Computed: Security level label
    get securityLevel() {
      const score = this.securityScore;
      if (score >= 90) return { label: 'Excellent', color: 'success' };
      if (score >= 70) return { label: 'Good', color: 'success' };
      if (score >= 50) return { label: 'Fair', color: 'warning' };
      if (score >= 30) return { label: 'Poor', color: 'warning' };
      return { label: 'Critical', color: 'error' };
    },

    // Computed: List of current vulnerabilities
    get vulnerabilities() {
      const vulns = [];

      if (!this.requirePkce) {
        vulns.push({
          id: 'no_pkce',
          name: 'Authorization Code Interception',
          severity: 'high',
          description: 'Without PKCE, authorization codes can be intercepted and replayed.',
          attacks: ['code_interception']
        });
      }

      if (!this.strictRedirectUri || this.allowWildcardRedirects) {
        vulns.push({
          id: 'weak_redirect',
          name: 'Redirect URI Manipulation',
          severity: 'critical',
          description: 'Loose redirect URI validation allows attackers to steal authorization codes.',
          attacks: ['redirect_manipulation']
        });
      }

      if (!this.validateAudience) {
        vulns.push({
          id: 'no_audience',
          name: 'Token Replay Across Services',
          severity: 'high',
          description: 'Tokens can be replayed against services that don\'t validate audience claims.',
          attacks: ['token_replay', 'audience_confusion']
        });
      }

      if (!this.requireStateParam) {
        vulns.push({
          id: 'no_state',
          name: 'CSRF on OAuth Callback',
          severity: 'high',
          description: 'Without state parameter, attackers can perform CSRF attacks on the callback.',
          attacks: ['csrf_callback']
        });
      }

      if (!this.shortTokenLifetime) {
        vulns.push({
          id: 'long_token',
          name: 'Extended Token Exposure',
          severity: 'medium',
          description: 'Long-lived tokens increase the window for token theft and replay.',
          attacks: ['token_theft']
        });
      }

      if (!this.httpsOnlyRedirects) {
        vulns.push({
          id: 'http_redirect',
          name: 'Insecure Redirect Transport',
          severity: 'high',
          description: 'HTTP redirects expose authorization codes to network attackers.',
          attacks: ['code_interception']
        });
      }

      return vulns;
    },

    // Computed: Which attacks would succeed with current config
    get possibleAttacks() {
      const attacks = new Set();
      this.vulnerabilities.forEach(v => {
        v.attacks.forEach(a => attacks.add(a));
      });
      return Array.from(attacks);
    },

    // Check if a specific attack would succeed
    isAttackPossible(attackId) {
      return this.possibleAttacks.includes(attackId);
    },

    // Get control that would block an attack
    getBlockingControl(attackId) {
      const controls = {
        'code_interception': { control: 'requirePkce', label: 'PKCE' },
        'redirect_manipulation': { control: 'strictRedirectUri', label: 'Strict Redirect URIs' },
        'token_replay': { control: 'validateAudience', label: 'Audience Validation' },
        'audience_confusion': { control: 'validateAudience', label: 'Audience Validation' },
        'csrf_callback': { control: 'requireStateParam', label: 'State Parameter' },
        'token_theft': { control: 'shortTokenLifetime', label: 'Short Token Lifetime' }
      };
      return controls[attackId] || null;
    },

    // Apply a preset configuration
    applyPreset(preset) {
      const presets = {
        insecure: {
          requirePkce: false,
          strictRedirectUri: false,
          allowWildcardRedirects: true,
          httpsOnlyRedirects: false,
          validateAudience: false,
          shortTokenLifetime: false,
          tokenLifetimeMinutes: 60,
          requireStateParam: false,
          enableRefreshTokenRotation: false,
          bindTokenToDevice: false,
          requireClientSecret: false
        },
        partial: {
          requirePkce: true,
          strictRedirectUri: false,
          allowWildcardRedirects: false,
          httpsOnlyRedirects: true,
          validateAudience: false,
          shortTokenLifetime: true,
          tokenLifetimeMinutes: 15,
          requireStateParam: true,
          enableRefreshTokenRotation: true,
          bindTokenToDevice: false,
          requireClientSecret: false
        },
        secure: {
          requirePkce: true,
          pkceMethod: 'S256',
          strictRedirectUri: true,
          allowWildcardRedirects: false,
          httpsOnlyRedirects: true,
          validateAudience: true,
          shortTokenLifetime: true,
          tokenLifetimeMinutes: 15,
          requireStateParam: true,
          enableRefreshTokenRotation: true,
          bindTokenToDevice: true,
          requireClientSecret: true
        }
      };

      if (presets[preset]) {
        Object.assign(this, presets[preset]);
        this.save();
      }
    },

    // Reset to defaults
    reset() {
      this.applyPreset('secure');
    },

    // Toggle a specific control
    toggle(control) {
      if (typeof this[control] === 'boolean') {
        this[control] = !this[control];
        this.save();
      }
    }
  });

  // Auto-save on changes
  Alpine.effect(() => {
    const config = Alpine.store('config');
    // Access all reactive properties to track them
    const _ = [
      config.requirePkce,
      config.strictRedirectUri,
      config.validateAudience,
      config.requireStateParam,
      config.shortTokenLifetime,
      config.httpsOnlyRedirects,
      config.allowWildcardRedirects,
      config.enableRefreshTokenRotation,
      config.bindTokenToDevice
    ];
    config.save();
  });
});
