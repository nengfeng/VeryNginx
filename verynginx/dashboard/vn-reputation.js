// vn-reputation.js - IP reputation module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-iploc.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnreputation'] = function createvnreputationModule(shared) {
        const { ctx, view, api, isValidIpLiteral, showConfirm, showToast } = shared;
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

    // Stale-response guard for the reputation data loader.
    const gRepData = shared.createStaleGuard();

    // ---- Load ----
    async function loadRepData() {
      const tok = gRepData.mark();
      repError.value = '';
      try {
        const [sd, fd, wd] = await Promise.all([
          api('GET', '/verynginx/reputation/stats'),
          api('GET', '/verynginx/reputation/flagged'),
          api('GET', '/verynginx/reputation/whitelist'),
        ]);
        if (!gRepData.isCurrent(tok)) return;
        repStats.value = sd.data;
        repFlagged.value = fd.data || [];
        repWhitelist.value = wd.data || [];
      } catch (e) {
        if (gRepData.isCurrent(tok)) repError.value = e.message;
      }
    }

    async function repClear(ip) {
      if (!await showConfirm({
        title: '清除 IP 声誉',
        message: `将清除 IP ${ip} 的所有声誉信号槽和待处理状态。\n\n`
          + '清除后该 IP 的分数归零，不再触发自动挑战或封禁，直到下一次被 WAF 命中累积新分数。\n'
          + '如果该 IP 当前正在封禁中，此操作仅清除声誉数据，内核封禁条目需单独清除。',
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
      if (!await showConfirm({
        title: '移除白名单',
        message: `从白名单中移除 ${ip}。\n\n`
          + '移除后该 IP 将重新接受声誉评分，触发 WAF 规则，并可能被自动封禁。\n'
          + '如果您是在排查误封后想恢复该 IP 的正常风控，请确认这是预期操作。',
        type: 'danger',
      })) return;
      try {
        await api('DELETE', '/verynginx/reputation/whitelist?ip=' + encodeURIComponent(ip));
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repPersist() {
      if (!await showConfirm({
        title: '持久化声誉数据',
        message: '将内存中的 IP 声誉分数和状态写入磁盘。\n\n'
          + '系统会在每 600 秒（10 分钟）自动持久化一次，手动触发通常用于：\n'
          + '• 怀疑数据未同步前的紧急保存\n'
          + '• 配合内核封禁重启前的数据快照\n'
          + '• 故障排查时确认磁盘数据最新。',
        type: 'primary',
      })) return;
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
    view('repStats', repStats);
    view('repFlagged', repFlagged);
    view('repWhitelist', repWhitelist);
    view('repError', repError);
    view('repNewWhitelist', repNewWhitelist);
    view('repLookupIP', repLookupIP);
    view('repLookupResult', repLookupResult);
    view('repClearBusy', repClearBusy);
    view('loadRepData', loadRepData);
    view('repClear', repClear);
    view('repAddWhitelist', repAddWhitelist);
    view('repRemoveWhitelist', repRemoveWhitelist);
    view('repPersist', repPersist);
    view('repLookup', repLookup);

    // Wipe per-session reputation data on logout.
    shared.onLogout(() => {
      repStats.value = null;
      repFlagged.value = [];
      repWhitelist.value = [];
      repError.value = '';
      repLookupResult.value = null;
      repNewWhitelist.value = '';
      repLookupIP.value = '';
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();