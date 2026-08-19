// app.js - Main entry point for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Namespace for module factories
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    const exports = new Map();
    function expose(name, value) { exports.set(name, value); }

    // Create shared context - ONLY initial state refs + core utilities
    // Domain modules declare their own functions locally (loadStatus, showToast, etc.)
    const ctx = {
        expose,
        // Initial state refs (from setup() initial state)
        page: null,
        dashTab: null,
        advTab: null,
        loading: null,
        loginUser: null,
        loginPass: null,
        loginError: null,
        status: null,
        connHistory: null,
        cfg: null,
        healthData: null,
        overview: null,
        dictUsage: null,
        cfgTab: null,
        theme: null,
        rawJson: null,
        jsonError: null,
        jsonSaving: null,
        statsData: null,
        statsType: null,
        statsError: null,
        expandedUri: null,
        editMatcherModal: null,
        // Core utilities
        api: null,
        store: null,
        isValidIpLiteral: null,
        refreshCsrf: null,
        refreshCsrfOnce: null,
        csrfToken: null,
    };

    // Initialize modules in dependency order
    // 1. Common (provides api, store, and populates initial state refs in ctx)
    if (window.VN.modules.vnCommon) {
        window.VN.modules.vnCommon(ctx);
    }

    // 2. Domain modules (all depend on ctx from common)
    const domainModules = [
        'vnDashboard',
        'vnConfig',
        'vnWaf',
        'vnFrequency',
        'vnGeoip',
        'vnReputation',
        'vnAdvanced',
        'vnKb',
    ];
    for (const name of domainModules) {
        if (window.VN.modules[name]) {
            window.VN.modules[name](ctx);
        }
    }

    // Mount Vue app
    const app = Vue.createApp({
        setup() {
            return Object.fromEntries(exports);
        }
    });

    app.mount('#app');

})();