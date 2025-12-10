// Consent Demo Component
// Implements the consent management UI for PRD-002
// Assumes backend is always available

document.addEventListener('alpine:init', () => {
    Alpine.data('consentDemo', () => ({
        // State
        loading: false,
        consentsLoading: false,
        error: null,
        success: null,

        // Authentication
        isAuthenticated: false,
        accessToken: null,

        // Demo users
        users: [
            { id: 'alice@example.com', name: 'Alice Smith' },
            { id: 'ahmed@example.com', name: 'Ahmed Tawfiq' },
            { id: 'diego@example.com', name: 'Diego Garcia' },
            { id: 'demo@example.com', name: 'Demo User' }
        ],
        currentUser: '',

        // Data - purposes are hardcoded based on backend validation
        purposes: [
            {
                id: 'login',
                name: 'User Login & Authentication',
                description: 'Allow authentication and session management',
                default_ttl_hours: 8760 // 365 days
            },
            {
                id: 'vc_issuance',
                name: 'Verifiable Credential Issuance',
                description: 'Allow issuing verifiable credentials on your behalf',
                default_ttl_hours: 8760 // 365 days
            },
            {
                id: 'registry_check',
                name: 'Registry Background Check',
                description: 'Perform background checks via registry integration',
                default_ttl_hours: 2160 // 90 days
            },
            {
                id: 'decision_evaluation',
                name: 'Decision Engine Evaluation',
                description: 'Run authorization decisions through policy engine',
                default_ttl_hours: 4320 // 180 days
            },
            {
                id: 'invalid_purpose',
                name: '⚠️ Invalid Purpose (Demo)',
                description: 'This purpose is not valid in the backend. Try granting it to see error handling.',
                default_ttl_hours: 720,
                isInvalid: true
            }
        ],
        consents: [],

        // Initialization
        init() {
            console.log('Consent Demo initialized');
            // Check if we have a token from OAuth flow
            this.checkForToken();
            // Auto-dismiss notifications after 5 seconds
            this.$watch('error', () => {
                if (this.error) {
                    setTimeout(() => { this.error = null; }, 5000);
                }
            });
            this.$watch('success', () => {
                if (this.success) {
                    setTimeout(() => { this.success = null; }, 5000);
                }
            });
        },

        // Check if OAuth token is available in URL or sessionStorage
        checkForToken() {
            // Look for token in URL hash (from OAuth redirect)
            const hash = window.location.hash;
            if (hash.includes('access_token=')) {
                const match = hash.match(/access_token=([^&]+)/);
                if (match) {
                    this.accessToken = match[1];
                    this.isAuthenticated = true;
                    // Clean up URL
                    window.history.replaceState({}, document.title, window.location.pathname);
                    this.success = '✅ Authenticated! You can now test consent endpoints.';
                    return;
                }
            }

            // Check sessionStorage for token
            const storedToken = sessionStorage.getItem('access_token');
            if (storedToken) {
                this.accessToken = storedToken;
                this.isAuthenticated = true;
                return;
            }

            // Not authenticated
            console.log('No token found - authentication required');
        },

        // Start OAuth flow to get token
        startOAuthFlow() {
            // Redirect to OAuth demo which will authenticate and come back here
            const returnUrl = window.location.href;
            // Store the return URL so OAuth demo knows where to redirect back
            sessionStorage.setItem('consent-demo-return', returnUrl);
            // Redirect to OAuth demo to get token
            window.location.href = '/demo.html?return=consent-demo.html';
        },

        // User selection
        async switchUser() {
            this.error = null;
            this.success = null;
            this.consents = [];
            
            if (!this.currentUser) {
                return;
            }

            // Load consents for the selected user
            await this.loadUserConsents();
        },

        // Load user consents from backend
        async loadUserConsents() {
            if (!this.currentUser) return;

            this.consentsLoading = true;
            this.error = null;

            try {
                // Fetch from backend: GET /auth/consent
                const response = await fetch('/auth/consent', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + this.accessToken
                    }
                });

                if (!response.ok) {
                    if (response.status === 401) {
                        throw new Error('Unauthorized - token may be expired. Please authenticate again.');
                    }
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();
                // Transform backend format to UI format
                this.consents = (data.consents || data.Consents || []).map(c => ({
                    id: c.id,
                    purpose: c.purpose,
                    status: c.status,
                    granted_at: c.granted_at,
                    expires_at: c.expires_at,
                    revoked_at: c.revoked_at
                }));
            } catch (err) {
                console.error('Failed to load consents:', err);
                this.error = `Failed to load consents: ${err.message}`;
                this.consents = [];
            } finally {
                this.consentsLoading = false;
            }
        },

        // Grant consent via backend
        async grantConsent(purposeId) {
            if (!this.currentUser) {
                this.error = 'Please select a user first';
                return;
            }

            if (!this.isAuthenticated || !this.accessToken) {
                this.error = 'Not authenticated. Please get an access token first.';
                return;
            }

            this.loading = true;
            this.error = null;
            this.success = null;

            const purpose = this.purposes.find(p => p.id === purposeId);
            const purposeName = purpose ? purpose.name : purposeId;

            try {
                // Check if trying to grant invalid purpose
                if (purpose && purpose.isInvalid) {
                    throw new Error(`Invalid purpose: "${purposeId}" is not valid. This demonstrates backend validation - invalid purposes will be rejected.`);
                }

                const payload = {
                    purposes: [purposeId]  // Backend expects array
                };

                // Call backend: POST /auth/consent
                const response = await fetch('/auth/consent', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + this.accessToken
                    },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();
                this.success = `✅ ${data.message || 'Consent granted for ' + purposeName}`;

                // Reload consents after granting
                await this.loadUserConsents();
            } catch (err) {
                console.error('Failed to grant consent:', err);
                this.error = `Failed to grant consent: ${err.message}`;
            } finally {
                this.loading = false;
            }
        },

        // Revoke consent via backend
        async revokeConsent(purposeId) {
            if (!this.currentUser) {
                this.error = 'Please select a user first';
                return;
            }

            if (!this.isAuthenticated || !this.accessToken) {
                this.error = 'Not authenticated. Please get an access token first.';
                return;
            }

            if (!confirm(`Are you sure you want to revoke consent for "${purposeId}"?`)) {
                return;
            }

            this.loading = true;
            this.error = null;
            this.success = null;

            const purpose = this.purposes.find(p => p.id === purposeId);
            const purposeName = purpose ? purpose.name : purposeId;

            try {
                const payload = {
                    purposes: [purposeId]  // Backend expects array
                };

                // Call backend: POST /auth/consent/revoke
                const response = await fetch('/auth/consent/revoke', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + this.accessToken
                    },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();
                this.success = `✅ ${data.message || 'Consent revoked for ' + purposeName}`;

                // Reload consents after revoking
                await this.loadUserConsents();
            } catch (err) {
                console.error('Failed to revoke consent:', err);
                this.error = `Failed to revoke consent: ${err.message}`;
            } finally {
                this.loading = false;
            }
        },

        // Helper: Check if purpose is already granted
        isGranted(purposeId) {
            return this.consents.some(c => c.purpose === purposeId && c.status === 'active');
        },

        // Helper: Get status badge class
        getStatusClass(status) {
            switch (status) {
                case 'active':
                    return 'pass';
                case 'revoked':
                    return 'fail';
                case 'expired':
                    return 'pending';
                default:
                    return '';
            }
        },

        // Helper: Format date/time
        formatDateTime(isoString) {
            if (!isoString) return 'N/A';
            const date = new Date(isoString);
            return date.toLocaleString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        },

        // Helper: Format duration in hours to human-readable
        formatDuration(hours) {
            if (!hours) return 'N/A';
            if (hours < 24) return `${hours}h`;
            const days = Math.floor(hours / 24);
            if (days < 30) return `${days}d`;
            const months = Math.floor(days / 30);
            if (months < 12) return `${months}mo`;
            const years = Math.floor(months / 12);
            return `${years}y`;
        },

        // Helper: Calculate time remaining
        getTimeRemaining(expiresAt) {
            if (!expiresAt) return '';
            const now = new Date();
            const expiry = new Date(expiresAt);
            const diff = expiry - now;

            if (diff < 0) return 'Expired';

            const days = Math.floor(diff / (1000 * 60 * 60 * 24));
            const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

            if (days > 0) return `${days}d ${hours}h remaining`;
            if (hours > 0) return `${hours}h remaining`;
            const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
            return `${minutes}m remaining`;
        }
    }));
});
