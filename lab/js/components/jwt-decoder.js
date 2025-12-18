/**
 * JWT Decoder Component
 * Decodes and displays JWT tokens with annotations
 */

document.addEventListener('alpine:init', () => {
  Alpine.data('jwtDecoder', (initialToken = '') => ({
    // Token input
    tokenInput: initialToken,

    // Decoded token
    decoded: null,

    // UI state
    activeSection: 'payload', // 'header' | 'payload' | 'signature'
    showAnnotations: true,
    securityIssues: [],

    // Timer for expiration countdown
    expirationTimer: null,
    timeUntilExpiration: null,

    init() {
      if (this.tokenInput) {
        this.decode();
      }

      // Set up expiration timer
      this.expirationTimer = setInterval(() => {
        this.updateExpiration();
      }, 1000);
    },

    destroy() {
      if (this.expirationTimer) {
        clearInterval(this.expirationTimer);
      }
    },

    // Decode the token
    decode() {
      if (!this.tokenInput || !this.tokenInput.trim()) {
        this.decoded = null;
        this.securityIssues = [];
        return;
      }

      this.decoded = JWTUtils.decode(this.tokenInput.trim());

      if (this.decoded) {
        this.securityIssues = JWTUtils.analyzeSecurityIssues(this.decoded);
        this.updateExpiration();
      } else {
        this.securityIssues = [{
          severity: 'error',
          claim: null,
          message: 'Invalid JWT format'
        }];
      }
    },

    // Set token from external source
    setToken(token) {
      this.tokenInput = token;
      this.decode();
    },

    // Clear token
    clear() {
      this.tokenInput = '';
      this.decoded = null;
      this.securityIssues = [];
      this.timeUntilExpiration = null;
    },

    // Update expiration countdown
    updateExpiration() {
      if (this.decoded) {
        this.timeUntilExpiration = JWTUtils.getTimeUntilExpiration(this.decoded);
      }
    },

    // Format expiration
    get formattedExpiration() {
      if (this.timeUntilExpiration === null) return 'No expiration';
      return JWTUtils.formatExpiration(this.timeUntilExpiration);
    },

    // Check if expired
    get isExpired() {
      return this.decoded && JWTUtils.isExpired(this.decoded);
    },

    // Get claim info
    getClaimInfo(claim) {
      return JWTUtils.getClaimInfo(claim);
    },

    // Format timestamp
    formatTimestamp(ts) {
      return JWTUtils.formatTimestamp(ts);
    },

    // Get pretty-printed section
    getSection(section) {
      if (!this.decoded) return '';

      switch (section) {
        case 'header':
          return JSON.stringify(this.decoded.header, null, 2);
        case 'payload':
          return JSON.stringify(this.decoded.payload, null, 2);
        case 'signature':
          return this.decoded.signature;
        default:
          return '';
      }
    },

    // Get raw section (base64)
    getRawSection(section) {
      if (!this.decoded || !this.decoded.raw) return '';
      return this.decoded.raw[section] || '';
    },

    // Copy token to clipboard
    async copyToken() {
      await FormatUtils.copyToClipboard(this.tokenInput);
    },

    // Copy section to clipboard
    async copySection(section) {
      await FormatUtils.copyToClipboard(this.getSection(section));
    },

    // Get severity icon/class
    getSeverityClass(severity) {
      const classes = {
        critical: 'text-error',
        error: 'text-error',
        warning: 'text-warning',
        info: 'text-info'
      };
      return classes[severity] || 'text-muted';
    },

    // Get severity badge class
    getSeverityBadge(severity) {
      const classes = {
        critical: 'badge-error',
        error: 'badge-error',
        warning: 'badge-warning',
        info: 'badge-info'
      };
      return classes[severity] || 'badge-neutral';
    },

    // Check if claim has security note
    hasSecurityNote(claim) {
      const info = this.getClaimInfo(claim);
      return info && info.security;
    },

    // Get claims with annotations
    get annotatedClaims() {
      if (!this.decoded || !this.decoded.payload) return [];

      return Object.entries(this.decoded.payload).map(([key, value]) => {
        const info = this.getClaimInfo(key);
        let displayValue = value;
        let formattedValue = null;

        // Format timestamps
        if (['exp', 'iat', 'nbf', 'auth_time'].includes(key) && typeof value === 'number') {
          formattedValue = this.formatTimestamp(value);
        }

        // Format arrays
        if (Array.isArray(value)) {
          displayValue = value.join(', ');
        }

        // Format objects
        if (typeof value === 'object' && value !== null) {
          displayValue = JSON.stringify(value);
        }

        return {
          key,
          value,
          displayValue,
          formattedValue,
          name: info.name,
          description: info.description,
          security: info.security
        };
      });
    },

    // Get header claims with annotations
    get annotatedHeaderClaims() {
      if (!this.decoded || !this.decoded.header) return [];

      const headerInfo = {
        alg: { name: 'Algorithm', description: 'Cryptographic algorithm used to secure the token' },
        typ: { name: 'Type', description: 'Token type (usually "JWT")' },
        kid: { name: 'Key ID', description: 'Identifier of the key used to sign the token' }
      };

      return Object.entries(this.decoded.header).map(([key, value]) => {
        const info = headerInfo[key] || { name: key, description: 'Custom header claim' };
        return {
          key,
          value,
          displayValue: typeof value === 'object' ? JSON.stringify(value) : value,
          name: info.name,
          description: info.description
        };
      });
    }
  }));
});
