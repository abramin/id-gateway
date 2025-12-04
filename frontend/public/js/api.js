// API Client for ID Gateway
// Based on PRD specifications and architecture docs

// Determine API base URL based on environment
const API_BASE_URL = (() => {
    // If running on port 3000 (docker frontend), use /api proxy
    if (window.location.port === '3000') {
        return '/api';
    }
    // If running locally on different port, directly call backend
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        return 'http://localhost:8080';
    }
    // Production - use same origin
    return '';
})();

class APIClient {
    constructor(baseURL = API_BASE_URL) {
        this.baseURL = baseURL;
        this.token = localStorage.getItem('access_token');
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };

        if (this.token && !options.skipAuth) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const config = {
            ...options,
            headers,
        };

        try {
            const response = await fetch(url, config);

            // Handle different response types
            if (response.status === 204) {
                return null;
            }

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error_description || data.error || data.message || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }

    // Auth Endpoints (PRD-001)
    async authorize(email, clientId = 'demo-client') {
        const data = await this.request('/auth/authorize', {
            method: 'POST',
            skipAuth: true,
            body: JSON.stringify({
                email,
                client_id: clientId,
                scopes: ['openid', 'profile'],
            }),
        });
        return data;
    }

    async getToken(sessionId) {
        const data = await this.request('/auth/token', {
            method: 'POST',
            skipAuth: true,
            body: JSON.stringify({
                session_id: sessionId,
                grant_type: 'session',
            }),
        });

        if (data.access_token) {
            this.token = data.access_token;
            localStorage.setItem('access_token', data.access_token);
            localStorage.setItem('id_token', data.id_token);
        }

        return data;
    }

    async getUserInfo() {
        return await this.request('/auth/userinfo', {
            method: 'GET',
        });
    }

    // Consent Endpoints (PRD-002)
    async grantConsent(purposes) {
        return await this.request('/auth/consent', {
            method: 'POST',
            body: JSON.stringify({ purposes }),
        });
    }

    async revokeConsent(purpose) {
        return await this.request('/auth/consent/revoke', {
            method: 'POST',
            body: JSON.stringify({ purpose }),
        });
    }

    // Registry Endpoints (PRD-003)
    async checkCitizen(nationalId) {
        return await this.request('/registry/citizen', {
            method: 'POST',
            body: JSON.stringify({ national_id: nationalId }),
        });
    }

    async checkSanctions(nationalId) {
        return await this.request('/registry/sanctions', {
            method: 'POST',
            body: JSON.stringify({ national_id: nationalId }),
        });
    }

    // VC Endpoints (PRD-004)
    async issueVC(type, nationalId) {
        return await this.request('/vc/issue', {
            method: 'POST',
            body: JSON.stringify({
                type,
                national_id: nationalId,
            }),
        });
    }

    async verifyVC(credentialId) {
        return await this.request('/vc/verify', {
            method: 'POST',
            body: JSON.stringify({ credential_id: credentialId }),
        });
    }

    // Decision Endpoints (PRD-005)
    async evaluateDecision(purpose, context) {
        return await this.request('/decision/evaluate', {
            method: 'POST',
            body: JSON.stringify({
                purpose,
                context,
            }),
        });
    }

    // User Data Rights Endpoints (PRD-006, PRD-007)
    async exportData() {
        return await this.request('/me/data-export', {
            method: 'GET',
        });
    }

    async deleteAccount() {
        const result = await this.request('/me', {
            method: 'DELETE',
        });

        // Clear local storage after deletion
        this.logout();

        return result;
    }

    logout() {
        this.token = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('id_token');
        localStorage.removeItem('user_email');
    }
}

// Create a global API client instance
window.api = new APIClient();
