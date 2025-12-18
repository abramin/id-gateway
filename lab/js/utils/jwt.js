/**
 * JWT Utilities
 * Decode, parse, and analyze JWT tokens
 */

const JWTUtils = {
  /**
   * Decode a JWT token without verification
   * @param {string} token - The JWT token string
   * @returns {object|null} Decoded token or null if invalid
   */
  decode(token) {
    try {
      if (!token || typeof token !== 'string') {
        return null;
      }

      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }

      const header = JSON.parse(this.base64UrlDecode(parts[0]));
      const payload = JSON.parse(this.base64UrlDecode(parts[1]));

      return {
        header,
        payload,
        signature: parts[2],
        raw: {
          header: parts[0],
          payload: parts[1],
          signature: parts[2]
        }
      };
    } catch (e) {
      console.error('Failed to decode JWT:', e);
      return null;
    }
  },

  /**
   * Base64 URL decode
   * @param {string} str - Base64 URL encoded string
   * @returns {string} Decoded string
   */
  base64UrlDecode(str) {
    // Replace URL-safe characters
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Pad with '=' to make it valid base64
    while (base64.length % 4) {
      base64 += '=';
    }

    return atob(base64);
  },

  /**
   * Base64 URL encode
   * @param {string} str - String to encode
   * @returns {string} Base64 URL encoded string
   */
  base64UrlEncode(str) {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  },

  /**
   * Check if a token is expired
   * @param {object} decoded - Decoded token object
   * @returns {boolean} True if expired
   */
  isExpired(decoded) {
    if (!decoded || !decoded.payload || !decoded.payload.exp) {
      return false;
    }
    return Date.now() >= decoded.payload.exp * 1000;
  },

  /**
   * Get time until expiration in seconds
   * @param {object} decoded - Decoded token object
   * @returns {number|null} Seconds until expiration or null
   */
  getTimeUntilExpiration(decoded) {
    if (!decoded || !decoded.payload || !decoded.payload.exp) {
      return null;
    }
    const expiresAt = decoded.payload.exp * 1000;
    return Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
  },

  /**
   * Format expiration time as human-readable string
   * @param {number} seconds - Seconds until expiration
   * @returns {string} Formatted time string
   */
  formatExpiration(seconds) {
    if (seconds === null || seconds === undefined) {
      return 'Unknown';
    }
    if (seconds <= 0) {
      return 'Expired';
    }

    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  },

  /**
   * Format Unix timestamp as human-readable date
   * @param {number} timestamp - Unix timestamp in seconds
   * @returns {string} Formatted date string
   */
  formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    return new Date(timestamp * 1000).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  },

  /**
   * Get claim descriptions for common JWT claims
   * @param {string} claim - Claim name
   * @returns {object} Claim info with description and security notes
   */
  getClaimInfo(claim) {
    const claims = {
      // Standard claims
      iss: {
        name: 'Issuer',
        description: 'Identifies the principal that issued the JWT',
        security: 'Always validate against expected issuer'
      },
      sub: {
        name: 'Subject',
        description: 'Identifies the subject of the JWT (usually user ID)',
        security: 'Used to identify the user - ensure it matches your records'
      },
      aud: {
        name: 'Audience',
        description: 'Identifies the recipients that the JWT is intended for',
        security: 'CRITICAL: Always validate! Prevents token replay across services'
      },
      exp: {
        name: 'Expiration Time',
        description: 'Expiration time after which the JWT must not be accepted',
        security: 'Always check expiration - reject expired tokens'
      },
      nbf: {
        name: 'Not Before',
        description: 'Time before which the JWT must not be accepted',
        security: 'Reject tokens used before this time'
      },
      iat: {
        name: 'Issued At',
        description: 'Time at which the JWT was issued',
        security: 'Can be used to determine token age'
      },
      jti: {
        name: 'JWT ID',
        description: 'Unique identifier for the JWT',
        security: 'Can be used to prevent token replay by tracking used JTIs'
      },

      // OIDC claims
      auth_time: {
        name: 'Authentication Time',
        description: 'Time when the end-user authentication occurred',
        security: 'Check for recent authentication when needed'
      },
      nonce: {
        name: 'Nonce',
        description: 'String value used to associate a client session with an ID Token',
        security: 'Mitigates replay attacks - must match the value sent in auth request'
      },
      acr: {
        name: 'Authentication Context Class Reference',
        description: 'Authentication context class that the authentication performed satisfied',
        security: 'Verify required authentication level was met'
      },
      amr: {
        name: 'Authentication Methods References',
        description: 'Authentication methods used in the authentication',
        security: 'Verify required authentication methods were used'
      },
      azp: {
        name: 'Authorized Party',
        description: 'The party to which the ID Token was issued',
        security: 'Should match the client_id of the application'
      },

      // Common custom claims
      scope: {
        name: 'Scope',
        description: 'OAuth 2.0 scopes granted to the token',
        security: 'Only grant access to resources within the granted scope'
      },
      email: {
        name: 'Email',
        description: 'User\'s email address',
        security: 'PII - handle according to privacy policy'
      },
      email_verified: {
        name: 'Email Verified',
        description: 'Whether the user\'s email has been verified',
        security: 'Important for account security decisions'
      },
      name: {
        name: 'Full Name',
        description: 'User\'s full name',
        security: 'PII - handle according to privacy policy'
      }
    };

    return claims[claim] || {
      name: claim,
      description: 'Custom claim',
      security: null
    };
  },

  /**
   * Analyze a token for security issues
   * @param {object} decoded - Decoded token object
   * @returns {array} Array of security findings
   */
  analyzeSecurityIssues(decoded) {
    const issues = [];

    if (!decoded || !decoded.payload) {
      issues.push({
        severity: 'error',
        claim: null,
        message: 'Invalid or malformed token'
      });
      return issues;
    }

    const { header, payload } = decoded;

    // Check algorithm
    if (header.alg === 'none') {
      issues.push({
        severity: 'critical',
        claim: 'alg',
        message: 'Token uses "none" algorithm - signature not verified!'
      });
    }

    if (header.alg === 'HS256') {
      issues.push({
        severity: 'warning',
        claim: 'alg',
        message: 'Token uses symmetric algorithm (HS256) - ensure secret is properly protected'
      });
    }

    // Check expiration
    if (!payload.exp) {
      issues.push({
        severity: 'warning',
        claim: 'exp',
        message: 'Token has no expiration time (exp claim missing)'
      });
    } else if (this.isExpired(decoded)) {
      issues.push({
        severity: 'error',
        claim: 'exp',
        message: 'Token has expired'
      });
    }

    // Check audience
    if (!payload.aud) {
      issues.push({
        severity: 'warning',
        claim: 'aud',
        message: 'Token has no audience claim - susceptible to replay across services'
      });
    }

    // Check issuer
    if (!payload.iss) {
      issues.push({
        severity: 'warning',
        claim: 'iss',
        message: 'Token has no issuer claim'
      });
    }

    // Check if token lifetime is too long
    if (payload.exp && payload.iat) {
      const lifetime = payload.exp - payload.iat;
      if (lifetime > 86400) { // More than 24 hours
        issues.push({
          severity: 'info',
          claim: 'exp',
          message: `Token has long lifetime (${Math.floor(lifetime / 3600)} hours)`
        });
      }
    }

    return issues;
  },

  /**
   * Create a syntax-highlighted HTML representation of a JWT
   * @param {object} decoded - Decoded token object
   * @returns {string} HTML string with highlighted parts
   */
  toHighlightedHTML(decoded) {
    if (!decoded) return '<span class="text-error">Invalid token</span>';

    const headerJson = JSON.stringify(decoded.header, null, 2);
    const payloadJson = JSON.stringify(decoded.payload, null, 2);

    return `<span class="jwt-header">${this.escapeHtml(headerJson)}</span>` +
           '<span class="jwt-dot">.</span>' +
           `<span class="jwt-payload">${this.escapeHtml(payloadJson)}</span>` +
           '<span class="jwt-dot">.</span>' +
           `<span class="jwt-signature">[signature]</span>`;
  },

  /**
   * Escape HTML special characters
   * @param {string} str - String to escape
   * @returns {string} Escaped string
   */
  escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
};

// Export for use in modules
if (typeof window !== 'undefined') {
  window.JWTUtils = JWTUtils;
}
