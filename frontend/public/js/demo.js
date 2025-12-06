// OAuth2 Demo Component
// Implements the complete Authorization Code Flow demonstration

document.addEventListener('alpine:init', () => {
    Alpine.data('oauthDemo', () => ({
        // Loading and error states
        loading: false,
        error: null,
        success: null,

        // Demo presets
        selectedPreset: '',
        presets: {
            basic: {
                email: 'demo@example.com',
                clientId: 'demo-client',
                redirectUri: 'https://example.com/callback',
                state: 'random-state-' + Math.random().toString(36).substring(7),
                scopes: ['openid', 'profile']
            },
            full: {
                email: 'fullaccess@example.com',
                clientId: 'full-client',
                redirectUri: 'https://example.com/callback',
                state: 'random-state-' + Math.random().toString(36).substring(7),
                scopes: ['openid', 'profile', 'email']
            },
            custom: {
                email: 'custom@example.com',
                clientId: 'custom-client',
                redirectUri: 'https://custom-app.com/callback',
                state: 'random-state-' + Math.random().toString(36).substring(7),
                scopes: ['openid', 'profile']
            }
        },

        // Form data
        form: {
            email: 'demo@example.com',
            clientId: 'demo-client',
            redirectUri: 'https://example.com/callback',
            state: 'random-state-' + Math.random().toString(36).substring(7),
            scopesText: 'openid\nprofile\nemail'
        },

        // Manual input fields for step 2 and 3 (JSON format)
        manualTokenRequestBody: JSON.stringify({
            grant_type: 'authorization_code',
            code: '<PASTE CODE HERE>',
            redirect_uri: 'https://example.com/callback',
            client_id: 'demo-client'
        }, null, 2),
        manualUserInfoHeaders: JSON.stringify({
            Authorization: 'Bearer <PASTE TOKEN HERE>'
        }, null, 2),
        jsonValidationError: null,

        // API Responses
        authorizeRequest: null,
        authorizeResponse: null,
        tokenRequest: null,
        tokenResponse: null,
        userInfoResponse: null,

        // Timeline tracking
        timeline: {
            authorize: {
                inProgress: false,
                completed: false,
                timestamp: null
            },
            token: {
                inProgress: false,
                completed: false,
                timestamp: null
            },
            userinfo: {
                inProgress: false,
                completed: false,
                timestamp: null
            }
        },

        init() {
            // Auto-dismiss notifications after 5 seconds
            this.$watch('error', (value) => {
                if (value) {
                    setTimeout(() => {
                        this.error = null;
                    }, 5000);
                }
            });

            this.$watch('success', (value) => {
                if (value) {
                    setTimeout(() => {
                        this.success = null;
                    }, 5000);
                }
            });

            // Auto-update Step 2 JSON when form values change
            this.$watch('form.redirectUri', () => {
                this.updateTokenRequestBody();
            });

            this.$watch('form.clientId', () => {
                this.updateTokenRequestBody();
            });

            // Start token expiration countdown timer
            setInterval(() => {
                // Force Alpine to re-evaluate token expiration displays
                if (this.tokenResponse) {
                    this.$nextTick(() => {
                        // This triggers Alpine's reactivity for time-based displays
                    });
                }
            }, 1000);
        },

        // Update Step 2 request body with current form values
        updateTokenRequestBody() {
            try {
                const currentBody = JSON.parse(this.manualTokenRequestBody);
                currentBody.redirect_uri = this.form.redirectUri;
                currentBody.client_id = this.form.clientId;
                this.manualTokenRequestBody = JSON.stringify(currentBody, null, 2);
            } catch (err) {
                // If JSON is invalid, don't update
                console.warn('Could not update token request body:', err);
            }
        },

        // Reset Step 2 JSON to template
        resetTokenRequestBody() {
            this.manualTokenRequestBody = JSON.stringify({
                grant_type: 'authorization_code',
                code: '<PASTE CODE HERE>',
                redirect_uri: this.form.redirectUri,
                client_id: this.form.clientId
            }, null, 2);
            this.jsonValidationError = null;
            this.success = 'Request body reset to template';
        },

        // Reset Step 3 JSON to template
        resetUserInfoHeaders() {
            this.manualUserInfoHeaders = JSON.stringify({
                Authorization: 'Bearer <PASTE TOKEN HERE>'
            }, null, 2);
            this.jsonValidationError = null;
            this.success = 'Request headers reset to template';
        },

        // JSON validation helper
        validateJSON(jsonString) {
            try {
                JSON.parse(jsonString.trim());
                return { valid: true, error: null };
            } catch (err) {
                return { valid: false, error: err.message };
            }
        },

        // Apply a demo preset
        applyPreset() {
            if (!this.selectedPreset) return;

            const preset = this.presets[this.selectedPreset];
            this.form.email = preset.email;
            this.form.clientId = preset.clientId;
            this.form.redirectUri = preset.redirectUri;
            this.form.state = preset.state;
            this.form.scopesText = preset.scopes.join('\n');
        },

        // Parse scopes from textarea
        getScopes() {
            return this.form.scopesText
                .split('\n')
                .map(s => s.trim())
                .filter(s => s.length > 0);
        },

        // Step 1: Authorization Request
        async authorize() {
            this.loading = true;
            this.error = null;
            this.timeline.authorize.inProgress = true;

            try {
                const scopes = this.getScopes();

                // Build request object
                this.authorizeRequest = {
                    email: this.form.email,
                    client_id: this.form.clientId,
                    redirect_uri: this.form.redirectUri,
                    state: this.form.state,
                    scopes: scopes
                };

                // Call API
                const response = await window.api.authorizeOAuth(
                    this.form.email,
                    this.form.clientId,
                    this.form.redirectUri,
                    this.form.state,
                    scopes
                );

                this.authorizeResponse = response;
                this.timeline.authorize.completed = true;
                this.timeline.authorize.timestamp = new Date();
                this.success = 'Authorization code issued successfully!';

            } catch (err) {
                this.error = err.message || 'Authorization request failed';
                console.error('Authorization error:', err);
            } finally {
                this.loading = false;
                this.timeline.authorize.inProgress = false;
            }
        },

        // Step 2: Token Exchange
        async exchangeToken() {
            // Validate JSON format
            const validation = this.validateJSON(this.manualTokenRequestBody);
            if (!validation.valid) {
                this.jsonValidationError = 'Invalid JSON: ' + validation.error;
                this.error = 'Please fix the JSON syntax error in the request body';
                return;
            }

            this.loading = true;
            this.error = null;
            this.jsonValidationError = null;
            this.timeline.token.inProgress = true;

            try {
                // Parse JSON request body
                const requestBody = JSON.parse(this.manualTokenRequestBody.trim());

                // Validate required fields
                if (!requestBody.code || requestBody.code === '<PASTE CODE HERE>') {
                    this.error = 'Please paste the authorization code in the "code" field';
                    return;
                }

                // Build request object for display
                this.tokenRequest = requestBody;

                // Call API
                const response = await window.api.exchangeCodeForToken(
                    requestBody.code,
                    requestBody.redirect_uri,
                    requestBody.client_id
                );

                this.tokenResponse = response;
                this.timeline.token.completed = true;
                this.timeline.token.timestamp = new Date();
                this.success = 'Tokens issued successfully!';

            } catch (err) {
                this.error = err.message || 'Token exchange failed';
                console.error('Token exchange error:', err);
            } finally {
                this.loading = false;
                this.timeline.token.inProgress = false;
            }
        },

        // Step 3: UserInfo Request
        async getUserInfo() {
            // Validate JSON format
            const validation = this.validateJSON(this.manualUserInfoHeaders);
            if (!validation.valid) {
                this.jsonValidationError = 'Invalid JSON: ' + validation.error;
                this.error = 'Please fix the JSON syntax error in the request headers';
                return;
            }

            this.loading = true;
            this.error = null;
            this.jsonValidationError = null;
            this.timeline.userinfo.inProgress = true;

            try {
                // Parse JSON headers
                const headers = JSON.parse(this.manualUserInfoHeaders.trim());

                // Validate Authorization header
                if (!headers.Authorization) {
                    this.error = 'Please add the Authorization header with Bearer token';
                    return;
                }

                if (headers.Authorization === 'Bearer <PASTE TOKEN HERE>') {
                    this.error = 'Please paste the access token after "Bearer " in the Authorization header';
                    return;
                }

                // Extract access token from "Bearer <token>" format
                const match = headers.Authorization.match(/^Bearer\s+(.+)$/i);
                if (!match) {
                    this.error = 'Authorization header must be in format: Bearer <token>';
                    return;
                }
                const accessToken = match[1];

                // Call API with access token
                const response = await window.api.getUserInfoWithToken(accessToken);

                this.userInfoResponse = response;
                this.timeline.userinfo.completed = true;
                this.timeline.userinfo.timestamp = new Date();
                this.success = 'User info retrieved successfully!';

            } catch (err) {
                // Enhanced error handling for JWT validation errors
                const errorMessage = err.message || 'UserInfo request failed';

                if (errorMessage.includes('expired')) {
                    this.error = 'Access token has expired. Please exchange a new token in Step 2.';
                } else if (errorMessage.includes('invalid token') || errorMessage.includes('unauthorized')) {
                    this.error = 'Invalid or malformed access token. Please check the token format.';
                } else {
                    this.error = errorMessage;
                }
                console.error('UserInfo error:', err);
            } finally {
                this.loading = false;
                this.timeline.userinfo.inProgress = false;
            }
        },

        // Reset the entire demo
        reset() {
            this.authorizeRequest = null;
            this.authorizeResponse = null;
            this.tokenRequest = null;
            this.tokenResponse = null;
            this.userInfoResponse = null;
            this.error = null;
            this.success = null;
            this.jsonValidationError = null;

            // Reset JSON fields to templates
            this.manualTokenRequestBody = JSON.stringify({
                grant_type: 'authorization_code',
                code: '<PASTE CODE HERE>',
                redirect_uri: this.form.redirectUri,
                client_id: this.form.clientId
            }, null, 2);

            this.manualUserInfoHeaders = JSON.stringify({
                Authorization: 'Bearer <PASTE TOKEN HERE>'
            }, null, 2);

            // Reset timeline
            this.timeline = {
                authorize: { inProgress: false, completed: false, timestamp: null },
                token: { inProgress: false, completed: false, timestamp: null },
                userinfo: { inProgress: false, completed: false, timestamp: null }
            };

            // Generate new state
            this.form.state = 'random-state-' + Math.random().toString(36).substring(7);

            this.success = 'Demo reset successfully';
        },

        // JWT Decoding helpers
        decodeJWT(token) {
            try {
                const parts = token.split('.');
                if (parts.length !== 3) {
                    return null;
                }

                const header = JSON.parse(atob(parts[0]));
                const payload = JSON.parse(atob(parts[1]));
                const signature = parts[2];

                return {
                    header,
                    payload,
                    signature,
                    raw: {
                        header: parts[0],
                        payload: parts[1],
                        signature: parts[2]
                    }
                };
            } catch (err) {
                console.error('Failed to decode JWT:', err);
                return null;
            }
        },

        // Get decoded access token
        getDecodedAccessToken() {
            if (!this.tokenResponse || !this.tokenResponse.access_token) {
                return null;
            }
            return this.decodeJWT(this.tokenResponse.access_token);
        },

        // Get decoded ID token
        getDecodedIDToken() {
            if (!this.tokenResponse || !this.tokenResponse.id_token) {
                return null;
            }
            return this.decodeJWT(this.tokenResponse.id_token);
        },

        // Check if token is expired
        isTokenExpired(decodedToken) {
            if (!decodedToken || !decodedToken.payload.exp) {
                return false;
            }
            return Date.now() >= decodedToken.payload.exp * 1000;
        },

        // Get time until expiration in seconds
        getTimeUntilExpiration(decodedToken) {
            if (!decodedToken || !decodedToken.payload.exp) {
                return null;
            }
            const expiresAt = decodedToken.payload.exp * 1000;
            const now = Date.now();
            return Math.max(0, Math.floor((expiresAt - now) / 1000));
        },

        // Format expiration time
        formatExpirationTime(seconds) {
            if (seconds === null || seconds === undefined) {
                return 'Unknown';
            }
            if (seconds === 0) {
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

        // Format Unix timestamp to readable date
        formatUnixTimestamp(timestamp) {
            if (!timestamp) return 'N/A';
            const date = new Date(timestamp * 1000);
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        },

        // Copy to clipboard helper
        async copyToClipboard(text) {
            try {
                await navigator.clipboard.writeText(text);
                this.success = 'Copied to clipboard!';
            } catch (err) {
                this.error = 'Failed to copy to clipboard';
            }
        },

        // Timeline status helpers
        getStepStatusClass(step) {
            const state = this.timeline[step];
            if (state.completed) return 'pass';
            if (state.inProgress) return 'pending';
            return 'fail';
        },

        getStepStatusText(step) {
            const state = this.timeline[step];
            if (state.completed) return 'Completed';
            if (state.inProgress) return 'In Progress';
            return 'Pending';
        },

        // Format duration (in nanoseconds from Go)
        formatDuration(nanoseconds) {
            const seconds = Math.floor(nanoseconds / 1000000000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);

            if (hours > 0) {
                return `${hours}h ${minutes % 60}m`;
            } else if (minutes > 0) {
                return `${minutes}m ${seconds % 60}s`;
            } else {
                return `${seconds}s`;
            }
        },

        // Format timestamp
        formatTime(date) {
            return date.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        },

        // Get completed steps count
        getCompletedSteps() {
            let count = 0;
            if (this.timeline.authorize.completed) count++;
            if (this.timeline.token.completed) count++;
            if (this.timeline.userinfo.completed) count++;
            return count;
        },
    }));
});
