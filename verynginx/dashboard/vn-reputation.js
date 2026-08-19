// vn-reputation.js - IP reputation module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-geoip.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnreputation'] = function createvnreputationModule(ctx) {
        const { expose, api, isValidIpLiteral, showConfirm, showToast } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Reputation State ----
    const repStats = ref(null);
    const repFlagged = ref([]);
    const repWhitelist = ref([]);
    const repError = ref('');
    const repNewWhitelist = ref('');
    const repLookupIP = ref('');
    const repLookupResult = ref(null);
    const repClearBusy = ref({});

    // ---- Load ----
    async function loadRepData() {
      repError.value = '';
      try {
        const [sd, fd, wd] = await Promise.all([
          api('GET', '/verynginx/reputation/stats'),
          api('GET', '/verynginx/reputation/flagged'),
          api('GET', '/verynginx/reputation/whitelist'),
        ]);
        repStats.value = sd.data;
        repFlagged.value = fd.data || [];
        repWhitelist.value = wd.data || [];
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repClear(ip) {
      if (!await showConfirm({
        title: '清除声誉分数',
        message: `清除 IP ${ip} 的声誉分数?`,
        type: 'danger',
        requireInput: true,
        inputLabel: `请输入 IP 地址 ${ip} 确认`,
        inputExpected: ip,
      })) return;
      repClearBusy.value[ip] = true;
      try {
        await api('POST', '/verynginx/reputation/clear?ip=' + encodeURIComponent(ip));
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      } finally {
        repClearBusy.value[ip] = false;
      }
    }

    async function repAddWhitelist() {
      const ip = repNewWhitelist.value.trim();
      if (!ip) return;
      // Client-side IP format validation (allows CIDR prefix for whitelist)
      if (!isValidIpLiteral(ip, true)) { repError.value = 'IP 格式无效: ' + ip; return; }
      try {
        await api('POST', '/verynginx/reputation/whitelist', { ip });
        repNewWhitelist.value = '';
        repError.value = '';
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repRemoveWhitelist(ip) {
      if (!await showConfirm({ title: '移除白名单', message: `从白名单移除 ${ip}?`, type: 'danger' })) return;
      try {
        await api('DELETE', '/verynginx/reputation/whitelist?ip=' + encodeURIComponent(ip));
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repPersist() {
      if (!await showConfirm({ title: '持久化声誉数据', message: '立即将 IP 声誉数据持久化到磁盘？', type: 'primary' })) return;
      try {
        await api('POST', '/verynginx/reputation/persist');
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repLookup() {
      const ip = repLookupIP.value.trim();
      if (!ip) return;
      if (!isValidIpLiteral(ip)) { repError.value = 'IP 格式无效: ' + ip; return; }
      repLookupResult.value = null;
      try {
        const d = await api('GET', '/verynginx/reputation/score?ip=' + encodeURIComponent(ip));
        repLookupResult.value = d.data;
      } catch (e) {
        repError.value = e.message;
      }
    }

    // ---- Exports ----
    expose('repStats', repStats);
    expose('repFlagged', repFlagged);
    expose('repWhitelist', repWhitelist);
    expose('repError', repError);
    expose('repNewWhitelist', repNewWhitelist);
    expose('repLookupIP', repLookupIP);
    expose('repLookupResult', repLookupResult);
    expose('repClearBusy', repClearBusy);
    expose('loadRepData', loadRepData);
    expose('repClear', repClear);
    expose('repAddWhitelist', repAddWhitelist);
    expose('repRemoveWhitelist', repRemoveWhitelist);
    expose('repPersist', repPersist);
    expose('repLookup', repLookup);

        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();