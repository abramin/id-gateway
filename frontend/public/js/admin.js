// Admin dashboard logic
// Mock data for demonstration - will be replaced with real API calls

document.addEventListener('alpine:init', () => {
    Alpine.data('adminApp', () => ({
        loading: false,
        regulatedMode: true,

        // Stats
        stats: {
            totalUsers: 0,
            activeSessions: 0,
            vcsIssued: 0,
            decisionsMade: 0,
        },

        // Recent decisions
        recentDecisions: [],

        // Active users
        activeUsers: [],

        // Consent statistics
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
            // Load initial data
            await this.loadMockData();

            // Start polling for updates every 5 seconds
            this.pollInterval = setInterval(() => {
                this.loadMockData();
            }, 5000);

            // Filter events initially
            this.filterAuditEvents();
        },

        destroy() {
            // Clean up polling when component is destroyed
            if (this.pollInterval) {
                clearInterval(this.pollInterval);
            }
        },

        async loadMockData() {
            // In a real implementation, these would be API calls
            // For now, we'll generate mock data to demonstrate the UI

            // Update stats
            this.stats.totalUsers = Math.floor(Math.random() * 50) + 10;
            this.stats.activeSessions = Math.floor(Math.random() * 20) + 5;
            this.stats.vcsIssued = Math.floor(Math.random() * 100) + 20;
            this.stats.decisionsMade = Math.floor(Math.random() * 200) + 50;

            // Generate mock recent decisions
            this.recentDecisions = this.generateMockDecisions(5);

            // Generate mock active users
            this.activeUsers = this.generateMockUsers(3);

            // Update consent stats
            this.consentStats.forEach(stat => {
                stat.total = this.stats.totalUsers;
                stat.granted = Math.floor(Math.random() * stat.total);
            });

            // Generate mock audit events
            if (this.auditEvents.length < 20) {
                this.auditEvents = this.generateMockAuditEvents(20);
            } else {
                // Add new event occasionally
                if (Math.random() > 0.7) {
                    this.auditEvents.unshift(this.generateMockAuditEvents(1)[0]);
                    if (this.auditEvents.length > 50) {
                        this.auditEvents.pop();
                    }
                }
            }

            this.filterAuditEvents();
        },

        generateMockDecisions(count) {
            const decisions = [];
            const purposes = ['age_verification', 'sanctions_screening', 'high_value_transfer'];
            const statuses = ['pass', 'fail', 'pass_with_conditions'];
            const reasons = [
                'all_checks_passed',
                'sanctioned',
                'underage',
                'missing_credential',
                'invalid_citizen',
            ];

            for (let i = 0; i < count; i++) {
                const status = statuses[Math.floor(Math.random() * statuses.length)];
                decisions.push({
                    id: `dec_${Date.now()}_${i}`,
                    purpose: purposes[Math.floor(Math.random() * purposes.length)],
                    status,
                    reason: reasons[Math.floor(Math.random() * reasons.length)],
                    userId: `user_${Math.random().toString(36).substr(2, 9)}`,
                    timestamp: this.formatTimestamp(new Date(Date.now() - Math.random() * 3600000)),
                });
            }

            return decisions;
        },

        generateMockUsers(count) {
            const users = [];
            const emails = ['alice@example.com', 'ahmed@example.com', 'diego@example.com', 'diana@example.com'];

            for (let i = 0; i < count; i++) {
                users.push({
                    id: `user_${Math.random().toString(36).substr(2, 9)}`,
                    email: emails[i % emails.length],
                    sessionCount: Math.floor(Math.random() * 3) + 1,
                    lastActive: this.formatTimestamp(new Date(Date.now() - Math.random() * 600000)),
                });
            }

            return users;
        },

        generateMockAuditEvents(count) {
            const events = [];
            const actions = [
                'decision_made',
                'consent_granted',
                'consent_revoked',
                'vc_issued',
                'registry_checked',
                'session_created',
                'token_issued',
            ];
            const purposes = [
                'age_verification',
                'sanctions_screening',
                'registry_check',
                'vc_issuance',
                'decision_evaluation',
            ];
            const decisions = ['granted', 'revoked', 'pass', 'fail', 'checked', 'issued'];

            for (let i = 0; i < count; i++) {
                const action = actions[Math.floor(Math.random() * actions.length)];
                events.push({
                    id: `evt_${Date.now()}_${i}`,
                    timestamp: this.formatTimestamp(new Date(Date.now() - Math.random() * 7200000)),
                    action,
                    purpose: purposes[Math.floor(Math.random() * purposes.length)],
                    decision: decisions[Math.floor(Math.random() * decisions.length)],
                    userId: `user_${Math.random().toString(36).substr(2, 6)}`,
                    reason: this.getReasonForAction(action),
                });
            }

            // Sort by timestamp (newest first)
            events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

            return events;
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
            const now = new Date();
            const diff = now - date;
            const seconds = Math.floor(diff / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);

            if (seconds < 60) {
                return `${seconds}s ago`;
            } else if (minutes < 60) {
                return `${minutes}m ago`;
            } else if (hours < 24) {
                return `${hours}h ago`;
            } else {
                return date.toLocaleString();
            }
        },

        toggleRegulatedMode() {
            this.regulatedMode = !this.regulatedMode;
            // In a real implementation, this would call an API to change the backend mode
            console.log('Regulated mode:', this.regulatedMode);
        },

        async refreshData() {
            this.loading = true;
            await this.loadMockData();
            setTimeout(() => {
                this.loading = false;
            }, 500);
        },
    }));
});
