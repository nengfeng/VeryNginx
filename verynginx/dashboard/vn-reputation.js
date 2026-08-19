// vn-reputation.js - Domain module for VeryNginx Dashboard
// Factory function pattern: receives ctx with shared dependencies

export function createvnreputationModule(ctx) {
    const { 
        expose, api, store, showToast, showConfirm, navigateTo,
        isValidIpLiteral, refreshCsrf, loadStatus, loadConfig
    } = ctx;
    
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
    // return {}; // No additional exports needed; expose() calls register everything
}