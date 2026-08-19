// vn-reputation.js - Domain module for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    
    window.VN.modules['vnreputation'] = function createvnreputationModule(ctx) {
        const { expose, api, store, page, dashTab, advTab, loading, loginUser, loginPass, loginError, status, connHistory, cfg, healthData, overview, dictUsage, cfgTab, theme, rawJson, jsonError, jsonSaving, statsData, statsType, statsError, expandedUri, editMatcherModal, isValidIpLiteral, refreshCsrf, refreshCsrfOnce, csrfToken } = ctx;
        
    // ---- Reputation State ----
    const repStats = ref(null);
        expose('repStats', repStats);
    const repFlagged = ref([]);
        expose('repFlagged', repFlagged);
    const repWhitelist = ref([]);
        expose('repWhitelist', repWhitelist);
    const repError = ref('');
        expose('repError', repError);
    const repNewWhitelist = ref('');
        expose('repNewWhitelist', repNewWhitelist);
    const repLookupIP = ref('');
        expose('repLookupIP', repLookupIP);
    const repLookupResult = ref(null);
        expose('repLookupResult', repLookupResult);
    const repClearBusy = ref({});
        expose('repClearBusy', repClearBusy);
        
        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();