/**
 * Security Panel Component
 * Reusable toggle panel for security configuration
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('securityPanel', (options = {}) => ({
    // Options
    showPresets: options.showPresets !== false,
    showScore: options.showScore !== false,
    compact: options.compact || false,
    readOnly: options.readOnly || false,

    // Local UI state
    expanded: {
      pkce: true,
      redirect: true,
      token: true,
      advanced: false
    },

    // Get config store
    get config() {
      return Alpine.store('config');
    },

    // Security score
    get score() {
      return this.config.securityScore;
    },

    get scoreLevel() {
      return this.config.securityLevel;
    },

    // Vulnerability count
    get vulnerabilityCount() {
      return this.config.vulnerabilities.length;
    },

    // Toggle a security control
    toggle(control) {
      if (this.readOnly) return;
      this.config.toggle(control);
    },

    // Apply a preset
    applyPreset(preset) {
      if (this.readOnly) return;
      this.config.applyPreset(preset);
    },

    // Toggle section expansion
    toggleSection(section) {
      this.expanded[section] = !this.expanded[section];
    },

    // Get stroke dashoffset for score circle
    get scoreCircleOffset() {
      const circumference = 2 * Math.PI * 52; // radius = 52
      return circumference - (this.score / 100) * circumference;
    },

    // Get score color
    get scoreColor() {
      if (this.score >= 70) return 'var(--success)';
      if (this.score >= 40) return 'var(--warning)';
      return 'var(--error)';
    },

    // Control definitions with labels and descriptions
    controls: {
      pkce: {
        title: 'PKCE Protection',
        items: [
          {
            key: 'requirePkce',
            label: 'Require PKCE',
            description: 'Proof Key for Code Exchange prevents authorization code interception',
            impact: 'high'
          },
          {
            key: 'pkceMethod',
            label: 'PKCE Method',
            description: 'S256 is recommended; plain should only be used if S256 is impossible',
            type: 'select',
            options: [
              { value: 'S256', label: 'S256 (Recommended)' },
              { value: 'plain', label: 'Plain (Not Recommended)' }
            ]
          }
        ]
      },
      redirect: {
        title: 'Redirect URI Validation',
        items: [
          {
            key: 'strictRedirectUri',
            label: 'Strict URI Matching',
            description: 'Only allow exact pre-registered redirect URIs',
            impact: 'critical'
          },
          {
            key: 'allowWildcardRedirects',
            label: 'Allow Wildcards',
            description: 'Allow wildcard patterns in redirect URIs (dangerous!)',
            inverted: true,
            impact: 'critical'
          },
          {
            key: 'httpsOnlyRedirects',
            label: 'HTTPS Only',
            description: 'Require HTTPS for all redirect URIs (except localhost)',
            impact: 'high'
          }
        ]
      },
      token: {
        title: 'Token Security',
        items: [
          {
            key: 'validateAudience',
            label: 'Validate Audience',
            description: 'Resource servers must validate the token audience claim',
            impact: 'high'
          },
          {
            key: 'shortTokenLifetime',
            label: 'Short Token Lifetime',
            description: 'Use short-lived access tokens (15 minutes vs 1 hour)',
            impact: 'medium'
          },
          {
            key: 'requireStateParam',
            label: 'Require State Parameter',
            description: 'Require and validate state parameter to prevent CSRF',
            impact: 'high'
          }
        ]
      },
      advanced: {
        title: 'Advanced Options',
        items: [
          {
            key: 'enableRefreshTokenRotation',
            label: 'Refresh Token Rotation',
            description: 'Issue new refresh token on each use, invalidating the old one',
            impact: 'medium'
          },
          {
            key: 'bindTokenToDevice',
            label: 'Device Binding',
            description: 'Bind tokens to the device that requested them',
            impact: 'medium'
          },
          {
            key: 'requireClientSecret',
            label: 'Require Client Secret',
            description: 'Require client authentication (not for public clients)',
            impact: 'low'
          }
        ]
      }
    },

    // Get impact badge class
    getImpactClass(impact) {
      const classes = {
        critical: 'badge-error',
        high: 'badge-warning',
        medium: 'badge-info',
        low: 'badge-neutral'
      };
      return classes[impact] || 'badge-neutral';
    }
  }));
});
