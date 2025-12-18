/**
 * Mock API Store
 * Simulates OAuth 2.0 endpoints with configurable security behaviors
 * Can be switched to live Credo API when ready
 */

document.addEventListener('alpine:init', () => {
  Alpine.store('mockApi', {
    // Mode: 'mock' or 'live'
    mode: 'mock',
    baseUrl: 'http://localhost:8080',

    // Simulated delay for realism (ms)
    simulatedDelay: 300,

    // Store for mock sessions/codes/tokens
    _mockState: {
      authorizationCodes: new Map(),
      accessTokens: new Map(),
      refreshTokens: new Map()
    },

    // Helper: Generate random ID
    _generateId(prefix = '') {
      return prefix + Math.random().toString(36).substring(2, 15) +
             Math.random().toString(36).substring(2, 15);
    },

    // Helper: Simulate network delay
    async _delay() {
      if (this.simulatedDelay > 0) {
        await new Promise(r => setTimeout(r, this.simulatedDelay));
      }
    },

    // Helper: Generate mock JWT
    _generateMockJwt(type, claims = {}) {
      const config = Alpine.store('config');
      const now = Math.floor(Date.now() / 1000);
      const lifetime = config.shortTokenLifetime
        ? config.tokenLifetimeMinutes * 60
        : 3600;

      const header = {
        alg: 'RS256',
        typ: 'JWT',
        kid: 'mock-key-1'
      };

      const payload = {
        iss: 'https://credo.example.com',
        sub: claims.userId || 'user_' + this._generateId(),
        aud: claims.audience || claims.clientId || 'demo-client',
        exp: now + lifetime,
        iat: now,
        nbf: now,
        jti: this._generateId('jti_'),
        ...claims
      };

      if (type === 'access') {
        payload.scope = claims.scope || 'openid profile';
        payload.token_type = 'access_token';
      } else if (type === 'id') {
        payload.auth_time = now;
        payload.nonce = claims.nonce;
        payload.email = claims.email || 'user@example.com';
        payload.name = claims.name || 'Demo User';
      }

      // Base64 encode (simplified - not real signing)
      const b64Header = btoa(JSON.stringify(header));
      const b64Payload = btoa(JSON.stringify(payload));
      const mockSignature = this._generateId('sig_');

      return `${b64Header}.${b64Payload}.${mockSignature}`;
    },

    /**
     * Authorization Endpoint
     * POST /auth/authorize
     */
    async authorize(params) {
      await this._delay();

      const config = Alpine.store('config');
      const {
        email,
        client_id,
        redirect_uri,
        state,
        scope,
        code_challenge,
        code_challenge_method,
        nonce
      } = params;

      // Validate required params
      if (!email || !client_id || !redirect_uri) {
        return {
          success: false,
          error: 'invalid_request',
          error_description: 'Missing required parameters: email, client_id, redirect_uri'
        };
      }

      // Check PKCE requirement
      if (config.requirePkce && !code_challenge) {
        return {
          success: false,
          error: 'invalid_request',
          error_description: 'PKCE code_challenge is required for this client',
          blocked_by: 'requirePkce'
        };
      }

      // Validate PKCE method
      if (code_challenge && config.pkceMethod === 'S256') {
        if (code_challenge_method && code_challenge_method !== 'S256') {
          return {
            success: false,
            error: 'invalid_request',
            error_description: 'Only S256 code_challenge_method is supported',
            blocked_by: 'pkceMethod'
          };
        }
      }

      // Validate redirect URI
      if (config.strictRedirectUri) {
        const allowedRedirects = [
          'https://app.example.com/callback',
          'https://demo.example.com/callback',
          'http://localhost:3000/callback',
          'http://localhost:8080/callback'
        ];

        if (!allowedRedirects.includes(redirect_uri)) {
          return {
            success: false,
            error: 'invalid_request',
            error_description: 'redirect_uri is not registered for this client',
            blocked_by: 'strictRedirectUri'
          };
        }
      }

      // Check for wildcard abuse
      if (!config.allowWildcardRedirects && redirect_uri.includes('*')) {
        return {
          success: false,
          error: 'invalid_request',
          error_description: 'Wildcard redirect URIs are not allowed',
          blocked_by: 'allowWildcardRedirects'
        };
      }

      // Check HTTPS requirement
      if (config.httpsOnlyRedirects) {
        const url = new URL(redirect_uri);
        if (url.protocol !== 'https:' && !url.hostname.match(/^(localhost|127\.0\.0\.1)$/)) {
          return {
            success: false,
            error: 'invalid_request',
            error_description: 'redirect_uri must use HTTPS',
            blocked_by: 'httpsOnlyRedirects'
          };
        }
      }

      // Check state parameter
      if (config.requireStateParam && !state) {
        return {
          success: false,
          error: 'invalid_request',
          error_description: 'state parameter is required',
          blocked_by: 'requireStateParam'
        };
      }

      // Generate authorization code
      const code = 'authz_' + this._generateId();

      // Store code with metadata
      this._mockState.authorizationCodes.set(code, {
        clientId: client_id,
        redirectUri: redirect_uri,
        scope: scope || 'openid profile',
        email: email,
        codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method || 'S256',
        nonce: nonce,
        state: state,
        createdAt: Date.now(),
        expiresAt: Date.now() + (10 * 60 * 1000), // 10 minutes
        used: false
      });

      return {
        success: true,
        code: code,
        state: state,
        redirect_uri: redirect_uri,
        expires_in: 600
      };
    },

    /**
     * Token Endpoint
     * POST /auth/token
     */
    async token(params) {
      await this._delay();

      const config = Alpine.store('config');
      const {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret,
        code_verifier,
        refresh_token
      } = params;

      // Handle refresh token grant
      if (grant_type === 'refresh_token') {
        return this._handleRefreshToken(params);
      }

      // Validate grant type
      if (grant_type !== 'authorization_code') {
        return {
          success: false,
          error: 'unsupported_grant_type',
          error_description: 'Only authorization_code grant is supported'
        };
      }

      // Validate code exists
      const codeData = this._mockState.authorizationCodes.get(code);
      if (!codeData) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'Authorization code is invalid or expired'
        };
      }

      // Check if code was already used
      if (codeData.used) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'Authorization code has already been used'
        };
      }

      // Check expiration
      if (Date.now() > codeData.expiresAt) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'Authorization code has expired'
        };
      }

      // Validate client_id matches
      if (codeData.clientId !== client_id) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'client_id does not match the authorization request'
        };
      }

      // Validate redirect_uri matches
      if (codeData.redirectUri !== redirect_uri) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'redirect_uri does not match the authorization request'
        };
      }

      // Validate PKCE
      if (config.requirePkce && codeData.codeChallenge) {
        if (!code_verifier) {
          return {
            success: false,
            error: 'invalid_grant',
            error_description: 'code_verifier is required for PKCE',
            blocked_by: 'requirePkce'
          };
        }

        // Simplified PKCE verification (in real impl, would hash and compare)
        // For mock, we just check it's present
        const isValidPkce = code_verifier && code_verifier.length >= 43;
        if (!isValidPkce) {
          return {
            success: false,
            error: 'invalid_grant',
            error_description: 'code_verifier is invalid',
            blocked_by: 'requirePkce'
          };
        }
      }

      // Check client secret if required
      if (config.requireClientSecret && !client_secret) {
        return {
          success: false,
          error: 'invalid_client',
          error_description: 'client_secret is required',
          blocked_by: 'requireClientSecret'
        };
      }

      // Mark code as used
      codeData.used = true;

      // Generate tokens
      const userId = 'user_' + this._generateId();
      const accessToken = this._generateMockJwt('access', {
        userId,
        clientId: client_id,
        scope: codeData.scope,
        email: codeData.email
      });

      const idToken = this._generateMockJwt('id', {
        userId,
        clientId: client_id,
        email: codeData.email,
        nonce: codeData.nonce
      });

      const refreshTokenValue = 'ref_' + this._generateId();

      // Store tokens
      this._mockState.accessTokens.set(accessToken, {
        userId,
        clientId: client_id,
        scope: codeData.scope,
        createdAt: Date.now()
      });

      this._mockState.refreshTokens.set(refreshTokenValue, {
        userId,
        clientId: client_id,
        scope: codeData.scope,
        createdAt: Date.now(),
        used: false
      });

      const expiresIn = config.shortTokenLifetime
        ? config.tokenLifetimeMinutes * 60
        : 3600;

      return {
        success: true,
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refreshTokenValue,
        token_type: 'Bearer',
        expires_in: expiresIn,
        scope: codeData.scope
      };
    },

    /**
     * Handle refresh token grant
     */
    async _handleRefreshToken(params) {
      const config = Alpine.store('config');
      const { refresh_token, client_id } = params;

      const tokenData = this._mockState.refreshTokens.get(refresh_token);
      if (!tokenData) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'Refresh token is invalid'
        };
      }

      // Check rotation - token can only be used once
      if (config.enableRefreshTokenRotation && tokenData.used) {
        return {
          success: false,
          error: 'invalid_grant',
          error_description: 'Refresh token has already been used (rotation enabled)'
        };
      }

      // Mark as used
      tokenData.used = true;

      // Generate new tokens
      const accessToken = this._generateMockJwt('access', {
        userId: tokenData.userId,
        clientId: client_id,
        scope: tokenData.scope
      });

      const newRefreshToken = 'ref_' + this._generateId();

      this._mockState.accessTokens.set(accessToken, {
        userId: tokenData.userId,
        clientId: client_id,
        scope: tokenData.scope,
        createdAt: Date.now()
      });

      this._mockState.refreshTokens.set(newRefreshToken, {
        userId: tokenData.userId,
        clientId: client_id,
        scope: tokenData.scope,
        createdAt: Date.now(),
        used: false
      });

      const expiresIn = config.shortTokenLifetime
        ? config.tokenLifetimeMinutes * 60
        : 3600;

      return {
        success: true,
        access_token: accessToken,
        refresh_token: config.enableRefreshTokenRotation ? newRefreshToken : refresh_token,
        token_type: 'Bearer',
        expires_in: expiresIn
      };
    },

    /**
     * UserInfo Endpoint
     * GET /auth/userinfo
     */
    async userinfo(accessToken) {
      await this._delay();

      const tokenData = this._mockState.accessTokens.get(accessToken);

      if (!tokenData) {
        return {
          success: false,
          error: 'invalid_token',
          error_description: 'Access token is invalid or expired'
        };
      }

      return {
        success: true,
        sub: tokenData.userId,
        email: 'user@example.com',
        email_verified: true,
        name: 'Demo User',
        given_name: 'Demo',
        family_name: 'User',
        updated_at: Math.floor(Date.now() / 1000)
      };
    },

    /**
     * Resource Server - Protected Resource
     * Simulates a resource server that may or may not validate audience
     */
    async resourceServer(accessToken, expectedAudience = 'resource-server') {
      await this._delay();

      const config = Alpine.store('config');

      // Decode token to check audience
      try {
        const parts = accessToken.split('.');
        if (parts.length !== 3) {
          return {
            success: false,
            error: 'invalid_token',
            error_description: 'Malformed token'
          };
        }

        const payload = JSON.parse(atob(parts[1]));

        // Check if audience validation is enabled
        if (config.validateAudience) {
          if (payload.aud !== expectedAudience) {
            return {
              success: false,
              error: 'invalid_token',
              error_description: `Token audience '${payload.aud}' does not match expected '${expectedAudience}'`,
              blocked_by: 'validateAudience'
            };
          }
        }

        // Check expiration
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
          return {
            success: false,
            error: 'invalid_token',
            error_description: 'Token has expired'
          };
        }

        // Success - return protected data
        return {
          success: true,
          data: {
            message: 'Protected resource accessed successfully',
            user: payload.email || payload.sub,
            accessed_at: new Date().toISOString(),
            audience_validated: config.validateAudience,
            warning: !config.validateAudience
              ? 'Audience was NOT validated - this token could be from any client!'
              : null
          }
        };

      } catch (e) {
        return {
          success: false,
          error: 'invalid_token',
          error_description: 'Failed to parse token'
        };
      }
    },

    /**
     * Attack Simulation: Code Interception
     * Simulates an attacker intercepting and replaying an authorization code
     */
    async simulateCodeInterception(code, attackerClientId) {
      await this._delay();

      const config = Alpine.store('config');
      const codeData = this._mockState.authorizationCodes.get(code);

      if (!codeData) {
        return {
          success: false,
          attack_result: 'failed',
          reason: 'Code not found or expired'
        };
      }

      // If PKCE is required, attacker can't replay without code_verifier
      if (config.requirePkce && codeData.codeChallenge) {
        return {
          success: false,
          attack_result: 'blocked',
          blocked_by: 'PKCE',
          reason: 'Attacker cannot replay code without the original code_verifier'
        };
      }

      // If code was already used
      if (codeData.used) {
        return {
          success: false,
          attack_result: 'blocked',
          blocked_by: 'One-time code',
          reason: 'Code has already been used'
        };
      }

      // Attack succeeds - code can be replayed
      return {
        success: true,
        attack_result: 'succeeded',
        reason: 'Code intercepted and ready for replay (no PKCE protection)',
        stolen_data: {
          code: code,
          redirect_uri: codeData.redirectUri,
          scope: codeData.scope
        }
      };
    },

    /**
     * Attack Simulation: Token Replay
     * Simulates replaying a token against a different resource server
     */
    async simulateTokenReplay(accessToken, targetAudience) {
      await this._delay();

      const config = Alpine.store('config');

      try {
        const parts = accessToken.split('.');
        const payload = JSON.parse(atob(parts[1]));

        // Check if target validates audience
        if (config.validateAudience) {
          if (payload.aud !== targetAudience) {
            return {
              success: false,
              attack_result: 'blocked',
              blocked_by: 'Audience Validation',
              reason: `Target resource server rejected token: audience '${payload.aud}' does not match '${targetAudience}'`
            };
          }
        }

        // Attack succeeds
        return {
          success: true,
          attack_result: 'succeeded',
          reason: 'Token accepted by target resource server (audience not validated)',
          warning: 'Resource server did not check the aud claim!',
          access_granted_to: targetAudience
        };

      } catch (e) {
        return {
          success: false,
          attack_result: 'failed',
          reason: 'Invalid token format'
        };
      }
    },

    /**
     * Attack Simulation: CSRF on Callback
     */
    async simulateCsrfAttack(attackerCode, victimSession) {
      await this._delay();

      const config = Alpine.store('config');

      if (config.requireStateParam) {
        return {
          success: false,
          attack_result: 'blocked',
          blocked_by: 'State Parameter',
          reason: 'Victim\'s browser rejected the callback: state parameter mismatch'
        };
      }

      return {
        success: true,
        attack_result: 'succeeded',
        reason: 'CSRF attack succeeded - victim\'s session now linked to attacker\'s account',
        warning: 'No state parameter validation!'
      };
    },

    /**
     * Clear all mock state (for testing)
     */
    reset() {
      this._mockState.authorizationCodes.clear();
      this._mockState.accessTokens.clear();
      this._mockState.refreshTokens.clear();
    }
  });
});
