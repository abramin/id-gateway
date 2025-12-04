// Main application logic for user portal
// Uses Alpine.js for reactivity

document.addEventListener('alpine:init', () => {
    Alpine.data('app', () => ({
        // State
        loading: false,
        error: null,
        success: null,
        isAuthenticated: false,
        regulatedMode: true, // Will be fetched from backend config

        // User data
        email: '',
        userEmail: localStorage.getItem('user_email') || '',
        userInfo: null,

        // Consent
        consentPurposes: [
            {
                id: 'registry_check',
                name: 'Registry Check',
                description: 'Allow checking citizen and sanctions registries',
                granted: false,
            },
            {
                id: 'vc_issuance',
                name: 'Credential Issuance',
                description: 'Allow issuing verifiable credentials',
                granted: false,
            },
            {
                id: 'decision_evaluation',
                name: 'Decision Evaluation',
                description: 'Allow making authorization decisions',
                granted: false,
            },
        ],

        // Identity verification
        nationalId: '',
        citizenRecord: null,
        sanctionsRecord: null,

        // Verifiable credentials
        credential: null,
        vcIssued: false,

        // Decision
        decisionPurpose: 'age_verification',
        decision: null,

        // Lifecycle
        async init() {
            // Check if user is already authenticated
            if (window.api.token) {
                await this.loadUserInfo();
            }
        },

        // Auth methods
        async login() {
            this.loading = true;
            this.error = null;

            try {
                // Step 1: Authorize and get session
                const authResult = await window.api.authorize(this.email);
                console.log('Authorization successful:', authResult);

                // Step 2: Exchange session for tokens
                const tokenResult = await window.api.getToken(authResult.session_id);
                console.log('Token received');

                // Save email
                localStorage.setItem('user_email', this.email);
                this.userEmail = this.email;

                // Load user info
                await this.loadUserInfo();

                this.success = 'Successfully signed in!';
            } catch (err) {
                console.error('Login failed:', err);
                this.error = err.message || 'Login failed. Please try again.';
            } finally {
                this.loading = false;
            }
        },

        async loadUserInfo() {
            try {
                this.userInfo = await window.api.getUserInfo();
                this.isAuthenticated = true;
                console.log('User info loaded:', this.userInfo);
            } catch (err) {
                console.error('Failed to load user info:', err);
                this.logout();
            }
        },

        logout() {
            window.api.logout();
            this.isAuthenticated = false;
            this.userInfo = null;
            this.userEmail = '';
            this.email = '';
            this.resetState();
        },

        resetState() {
            this.citizenRecord = null;
            this.sanctionsRecord = null;
            this.credential = null;
            this.vcIssued = false;
            this.decision = null;
            this.consentPurposes.forEach(p => p.granted = false);
        },

        // Consent methods
        async toggleConsent(purpose) {
            this.loading = true;
            this.error = null;

            try {
                if (purpose.granted) {
                    // Revoke consent
                    await window.api.revokeConsent(purpose.id);
                    purpose.granted = false;
                    this.success = `Consent revoked for ${purpose.name}`;
                } else {
                    // Grant consent
                    await window.api.grantConsent([purpose.id]);
                    purpose.granted = true;
                    this.success = `Consent granted for ${purpose.name}`;
                }
            } catch (err) {
                console.error('Consent operation failed:', err);
                this.error = err.message || 'Failed to update consent';
            } finally {
                this.loading = false;
            }
        },

        // Registry methods
        async checkCitizen() {
            if (!this.nationalId) {
                this.error = 'Please enter a National ID';
                return;
            }

            this.loading = true;
            this.error = null;

            try {
                this.citizenRecord = await window.api.checkCitizen(this.nationalId);
                this.success = 'Citizen record retrieved';
                console.log('Citizen record:', this.citizenRecord);
            } catch (err) {
                console.error('Citizen check failed:', err);
                this.error = err.message || 'Citizen check failed';
            } finally {
                this.loading = false;
            }
        },

        async checkSanctions() {
            if (!this.nationalId) {
                this.error = 'Please enter a National ID';
                return;
            }

            this.loading = true;
            this.error = null;

            try {
                this.sanctionsRecord = await window.api.checkSanctions(this.nationalId);
                this.success = 'Sanctions check completed';
                console.log('Sanctions record:', this.sanctionsRecord);
            } catch (err) {
                console.error('Sanctions check failed:', err);
                this.error = err.message || 'Sanctions check failed';
            } finally {
                this.loading = false;
            }
        },

        // VC methods
        async issueVC() {
            if (!this.nationalId) {
                this.error = 'Please enter a National ID';
                return;
            }

            this.loading = true;
            this.error = null;

            try {
                this.credential = await window.api.issueVC('AgeOver18', this.nationalId);
                this.vcIssued = true;
                this.success = 'Credential issued successfully!';
                console.log('VC issued:', this.credential);
            } catch (err) {
                console.error('VC issuance failed:', err);
                this.error = err.message || 'Failed to issue credential';
            } finally {
                this.loading = false;
            }
        },

        // Decision methods
        async evaluateDecision() {
            if (!this.nationalId) {
                this.error = 'Please enter a National ID';
                return;
            }

            this.loading = true;
            this.error = null;

            try {
                this.decision = await window.api.evaluateDecision(this.decisionPurpose, {
                    national_id: this.nationalId,
                });
                this.success = 'Decision evaluated';
                console.log('Decision result:', this.decision);
            } catch (err) {
                console.error('Decision evaluation failed:', err);
                this.error = err.message || 'Decision evaluation failed';
            } finally {
                this.loading = false;
            }
        },

        // Data rights methods
        async exportData() {
            this.loading = true;
            this.error = null;

            try {
                const data = await window.api.exportData();

                // Download as JSON file
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `my-data-${new Date().toISOString()}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                this.success = 'Data exported successfully!';
            } catch (err) {
                console.error('Data export failed:', err);
                this.error = err.message || 'Failed to export data';
            } finally {
                this.loading = false;
            }
        },

        async deleteAccount() {
            if (!confirm('Are you sure you want to delete your account? This cannot be undone!')) {
                return;
            }

            if (!confirm('This will permanently delete all your personal data. Audit logs will be retained but pseudonymized. Continue?')) {
                return;
            }

            this.loading = true;
            this.error = null;

            try {
                const result = await window.api.deleteAccount();
                alert(`Account deleted successfully!\n\nDeleted: ${result.deleted.join(', ')}\nRetained: ${result.retained.join(', ')}\n\n${result.note}`);

                // Logout will be called by the API client
                this.isAuthenticated = false;
                this.resetState();
            } catch (err) {
                console.error('Account deletion failed:', err);
                this.error = err.message || 'Failed to delete account';
            } finally {
                this.loading = false;
            }
        },
    }));
});
