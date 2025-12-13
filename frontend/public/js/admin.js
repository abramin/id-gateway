// Admin dashboard logic
// Uses real API calls to backend admin endpoints

// Determine API base URL based on environment
// Admin endpoints are on port 8090 (separate admin server)
function getAPIBase() {
    if (window.location.port === "3000") {
        // Docker: nginx will proxy /api/admin to backend:8090
        return "/api/admin";
    }
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
        // Local dev: admin server runs on port 8090
        return "http://localhost:8090";
    }
    // Production: admin server on same host, different port
    return window.location.protocol + "//" + window.location.hostname + ":8090";
}

document.addEventListener('alpine:init', () => {
    Alpine.data('adminApp', () => ({
        loading: false,
        regulatedMode: true,
        adminToken: '',
        showTokenInput: false,

        // Stats
        stats: {
            totalUsers: 0,
            activeSessions: 0,
            vcsIssued: 0,
            decisionsMade: 0,
        },

        // Recent decisions (derived from audit events)
        recentDecisions: [],

        // Active users
        activeUsers: [],

        // Consent statistics (not yet implemented in backend)
        consentStats: [
            {
                purpose: 'registry_check',
                name: 'Registry Check',
                granted: 0,
                total: 0,
            },
            {
                purpose: 'vc_issuance',
                name: 'VC Issuance',
                granted: 0,
                total: 0,
            },
            {
                purpose: 'decision_evaluation',
                name: 'Decision Evaluation',
                granted: 0,
                total: 0,
            },
        ],

        // Audit events
        auditEvents: [],
        filteredAuditEvents: [],
        auditFilter: 'all',

        // Polling interval
        pollInterval: null,

        async init() {
            // Try to get admin token from localStorage
            this.adminToken = localStorage.getItem('admin_token') || '';

            // If no token, show input
            if (!this.adminToken) {
                this.showTokenInput = true;
            } else {
                // Load initial data
                await this.loadRealData();

                // Start polling for updates every 10 seconds
                this.pollInterval = setInterval(() => {
                    this.loadRealData();
                }, 10000);
            }

            // Filter events initially
            this.filterAuditEvents();
        },

        destroy() {
            // Clean up polling when component is destroyed
            if (this.pollInterval) {
                clearInterval(this.pollInterval);
            }
        },

        async loadRealData() {
            if (!this.adminToken) {
                return;
            }

            try {
                // Load stats
                await this.loadStats();

                // Load users
                await this.loadUsers();

                // Load audit events
                await this.loadAuditEvents();

                this.filterAuditEvents();
            } catch (err) {
                console.error('Failed to load real data:', err);
            }
        },

        async loadStats() {
            const apiBase = getAPIBase();
            try {
                const res = await fetch(`${apiBase}/admin/stats`, {
                    headers: {
                        'X-Admin-Token': this.adminToken,
                    }
                });

                if (res.ok) {
                    const data = await res.json();
                    this.stats = {
                        totalUsers: data.total_users || 0,
                        activeSessions: data.active_sessions || 0,
                        vcsIssued: data.vcs_issued || 0,
                        decisionsMade: data.decisions_made || 0,
                    };
                } else if (res.status === 401 || res.status === 403) {
                    console.warn('Admin token is invalid or expired');
                    this.showTokenInput = true;
                }
            } catch (err) {
                console.error('Failed to load stats:', err);
            }
        },

        async loadUsers() {
            const apiBase = getAPIBase();
            try {
                const res = await fetch(`${apiBase}/admin/users`, {
                    headers: {
                        'X-Admin-Token': this.adminToken,
                    }
                });

                if (res.ok) {
                    const data = await res.json();
                    this.activeUsers = (data.users || []).map(user => ({
                        id: user.id,
                        email: user.email,
                        sessionCount: user.session_count || 0,
                        lastActive: user.last_active ? this.formatTimestamp(new Date(user.last_active)) : 'Never',
                    }));

                    // Update consent stats total based on user count
                    this.consentStats.forEach(stat => {
                        stat.total = data.total || 0;
                        // For now, set granted to 0 since we don't have this data yet
                        stat.granted = 0;
                    });
                }
            } catch (err) {
                console.error('Failed to load users:', err);
            }
        },

        async loadAuditEvents() {
            const apiBase = getAPIBase();
            try {
                const res = await fetch(`${apiBase}/admin/audit/recent?limit=50`, {
                    headers: {
                        'X-Admin-Token': this.adminToken,
                    }
                });

                if (res.ok) {
                    const data = await res.json();
                    this.auditEvents = (data.events || []).map(event => ({
                        id: (event.user_id || 'unknown') + '_' + (event.timestamp || Date.now()),
                        timestamp: event.timestamp ? this.formatTimestamp(new Date(event.timestamp)) : 'Unknown',
                        action: event.action || 'unknown',
                        purpose: event.purpose || 'N/A',
                        decision: event.decision || 'N/A',
                        userId: event.user_id || 'unknown',
                        reason: this.getReasonForAction(event.action),
                    }));

                    // Extract recent decisions from audit events
                    this.extractRecentDecisions();
                }
            } catch (err) {
                console.error('Failed to load audit events:', err);
            }
        },

        extractRecentDecisions() {
            // Filter audit events for decision_made actions
            this.recentDecisions = this.auditEvents
                .filter(event => event.action === 'decision_made')
                .slice(0, 5)
                .map(event => ({
                    id: event.id,
                    purpose: event.purpose,
                    status: event.decision === 'pass' ? 'pass' : (event.decision === 'fail' ? 'fail' : 'pass_with_conditions'),
                    reason: event.reason,
                    userId: event.userId,
                    timestamp: event.timestamp,
                }));
        },

        filterAuditEvents() {
            if (this.auditFilter === 'all') {
                this.filteredAuditEvents = this.auditEvents;
            } else {
                this.filteredAuditEvents = this.auditEvents.filter(
                    event => event.action === this.auditFilter
                );
            }
        },

        formatTimestamp(date) {
            if (!date || isNaN(date.getTime())) {
                return 'Unknown';
            }

            const now = new Date();
            const diff = now - date;
            const seconds = Math.floor(diff / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);

            if (seconds < 0) {
                // Future date, just show it
                return date.toLocaleString();
            } else if (seconds < 60) {
                return `${seconds}s ago`;
            } else if (minutes < 60) {
                return `${minutes}m ago`;
            } else if (hours < 24) {
                return `${hours}h ago`;
            } else {
                return date.toLocaleString();
            }
        },

        getReasonForAction(action) {
            const reasons = {
                decision_made: 'all_checks_passed',
                consent_granted: 'user_action',
                consent_revoked: 'user_action',
                vc_issued: 'age_credential',
                registry_checked: 'identity_verification',
                session_created: 'user_login',
                token_issued: 'authentication',
            };
            return reasons[action] || 'system';
        },

        toggleRegulatedMode() {
            this.regulatedMode = !this.regulatedMode;
            console.log('Regulated mode:', this.regulatedMode);
        },

        async refreshData() {
            this.loading = true;
            await this.loadRealData();
            setTimeout(() => {
                this.loading = false;
            }, 500);
        },

        saveAdminToken() {
            if (this.adminToken) {
                localStorage.setItem('admin_token', this.adminToken);
                this.showTokenInput = false;
                this.refreshData();
                // Start polling
                if (!this.pollInterval) {
                    this.pollInterval = setInterval(() => {
                        this.loadRealData();
                    }, 10000);
                }
            }
        },

        clearAdminToken() {
            this.adminToken = '';
            localStorage.removeItem('admin_token');
            this.showTokenInput = true;
            // Stop polling
            if (this.pollInterval) {
                clearInterval(this.pollInterval);
                this.pollInterval = null;
            }
            // Reset all data
            this.stats = {
                totalUsers: 0,
                activeSessions: 0,
                vcsIssued: 0,
                decisionsMade: 0,
            };
            this.activeUsers = [];
            this.auditEvents = [];
            this.recentDecisions = [];
            this.filterAuditEvents();
        },
    }));
});
