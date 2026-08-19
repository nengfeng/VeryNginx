// app.js - Main entry point for VeryNginx Dashboard
// Assembles all domain modules and mounts Vue app

import { createCommonModule } from './vn-common.js';
import { createVnDashboardModule } from './vn-dashboard.js';
import { createVnConfigModule } from './vn-config.js';
import { createVnWafModule } from './vn-waf.js';
import { createVnFrequencyModule } from './vn-frequency.js';
import { createVnGeoipModule } from './vn-geoip.js';
import { createVnReputationModule } from './vn-reputation.js';
import { createVnAdvancedModule } from './vn-advanced.js';
import { createVnKbModule } from './vn-kb.js';

const exports = new Map();
function expose(name, value) { exports.set(name, value); }

// Create shared context
const ctx = {
    expose,
    // These will be populated by createCommonModule
    api: null,
    store: null,
    showToast: null,
    showConfirm: null,
    navigateTo: null,
    isValidIpLiteral: null,
    refreshCsrf: null,
    loadStatus: null,
    loadConfig: null,
};

// Initialize common module (provides api, store, etc.)
createCommonModule(ctx);

// Now ctx has api, store, etc. - initialize domain modules
createVnDashboardModule(ctx);
createVnConfigModule(ctx);
createVnWafModule(ctx);
createVnFrequencyModule(ctx);
createVnGeoipModule(ctx);
createVnReputationModule(ctx);
createVnAdvancedModule(ctx);
createVnKbModule(ctx);

// Mount Vue app
const app = Vue.createApp({
    setup() {
        return Object.fromEntries(exports);
    }
});

app.mount('#app');

// Global unhandled rejection handler for session_expired
window.addEventListener('unhandledrejection', (ev) => {
    const reason = ev && ev.reason;
    if (reason && reason.message === 'session_expired') {
        ev.preventDefault();
    }
});