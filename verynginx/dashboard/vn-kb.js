// vn-kb.js - Kernel blocking module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded LAST (after all domain modules).

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnkb'] = function createvnkbModule(shared) {
        const { ctx, view, api, page, status, connHistory, isValidIpLiteral, showToast, showConfirm } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Kernel Blocking State ----
    const kbStatus = ref({
      configured: { enabled: false, mode: 'observe', emergency_pause: false, topology: 'unknown', protected_addresses: [], protected_ports: [] },
      effective: { global_mode: 'disabled', global_install_reachable: false, scanner: { mode: 'disabled', reason_codes: [] }, cc: { mode: 'disabled', reason_codes: [] }, reason_codes: [] },
      health: { state: 'unknown' },
      counters: { installed: 0, candidates: 0, rejected: 0, degraded: 0, rate_limited: 0, paused: 0, installed_scanner: 0, installed_cc: 0, installed_manual: 0, desired: 0, drift: 0 },
      promotion_bucket: { tokens_available: 0, rate_limited_recent: 0 },
      migration: { status: 'unknown' },
      counter_namespace: 'v1',
      cc_rules: [],
      lifecycle: {},
      whitelist_generation: {},
      last_reconcile: null,
    });
    const kbEntries = ref([]);
    const kbCandidates = ref([]);
    const kbTimeline = ref([]);
    const kbTimelineFilter = ref('');
    const kbEntriesNext = ref(null);
    const kbCandidatesNext = ref(null);
    const kbEntriesPrev = ref([]);
    const kbCandidatesPrev = ref([]);
    const kbEntriesCurrentCursor = ref(null);
    const kbCandidatesCurrentCursor = ref(null);
    const kbBucketHistory = ref([]);
    const kbBucketHistoryLoading = ref(false);
    const kbBucketHistoryError = ref('');
    const kbDiff = ref({ missing_in_kernel: [], orphan_in_kernel: [], desired_count: 0, actual_count: 0 });
    const kbDiffError = ref('');
    const kbTab = ref('entries');
    const kbNewIP = ref('');
    const kbNewPolicy = ref('scanner');
    const kbNewTTL = ref(300);
    const kbError = ref('');
    const kbBusy = ref(false);
    const kbFilterPolicy = ref('');
    const kbFilterState = ref('');
    const kbFilterIP = ref('');
    const kbForm = reactive({
      enabled: false,
      mode: 'observe',
      topology: 'direct',
      protected_addresses_str: '',
      protected_ports_str: '',
      cc_enforce_ready: false,
      scanner_enabled: true,
      cc_enabled: true,
    });
    const kbDetail = reactive({ show: false, entry: null });
    const kbDetailJson = computed(() => kbDetail.entry ? JSON.stringify(kbDetail.entry, null, 2) : '');
    const kbFormDirty = ref(false);
    function kbMarkFormDirty() { kbFormDirty.value = true; }

    // Expansion state for CC rule rows. Kept in a Set keyed by rule_id so it
    // survives status reloads (the API returns fresh cc_rules objects each time,
    // so storing _expanded on the API object would reset on every refresh).
    const expandedCcRules = reactive(new Set());
    function toggleCcRule(id) {
      if (expandedCcRules.has(id)) expandedCcRules.delete(id);
      else expandedCcRules.add(id);
    }

    // Stale-response guards for list/timeline loaders (rapid filter/page
    // switches must not let a slow old response overwrite fresh state).
    const gKbEntries = shared.createStaleGuard();
    const gKbCandidates = shared.createStaleGuard();
    const gKbTimeline = shared.createStaleGuard();
    const gKbDashboard = shared.createStaleGuard();
    const gKbBucket = shared.createStaleGuard();

    const KB_REASON_HELP = {
      global_disabled: { title: '内核封禁已禁用', advice: '启用全局开关，然后从观察模式开始。' },
      global_observe: { title: '全局模式为观察', advice: '观察模式仅收集候选。检查清单变绿后切换到执行模式。' },
      helper_unavailable: { title: '防火墙 Helper 不可达', advice: '启动 firewall-helper.socket 并检查 /run/verynginx/firewall-helper.sock。' },
      topology: { title: '拓扑阻止执行安装', advice: '设置 topology=direct 并在配置中配置受保护地址/端口。' },
      emergency_pause: { title: '紧急暂停已开启', advice: '点击恢复晋升以允许新的自动安装。' },
      family_disabled: { title: '地址族已禁用', advice: '在内核封禁下启用 ipv4 和/或 ipv6。' },
      disabled_with_active_entries: { title: '已禁用但内核条目仍存在', advice: '条目按 TTL 过期，或在确认后使用刷新自动集合。' },
      scanner_disabled: { title: '扫描器策略已禁用', advice: '如果需要扫描器晋升，请启用扫描器策略。' },
      cc_disabled: { title: 'CC 策略已禁用', advice: '启用 CC 策略并配置规则 ID。' },
      no_rule_ids: { title: '未配置 CC 规则 ID', advice: '在内核封禁 CC 下添加频率规则 ID。' },
      cc_not_enforce_ready: { title: 'CC 未就绪执行', advice: '完成迁移/切换/校准，然后设置 cc.enforce_ready=true。' },
      counter_namespace_not_v2: { title: '频率计数器命名空间不是 v2', advice: '运行频率规则 ID 迁移并完成 v2 切换。' },
      invalid_rule_ref: { title: 'CC 规则引用无效', advice: '修复或移除无效的规则 ID 以使所有引用可解析。' },
      helper_unreachable: { title: 'Helper 不可达', advice: '恢复 Helper 进程/套接字。' },
    };

    function kbCollectReasonCodes() {
      const codes = [];
      const eff = kbStatus.value.effective || {};
      (eff.reason_codes || []).forEach(c => codes.push(c));
      if (eff.scanner && eff.scanner.reason_codes) eff.scanner.reason_codes.forEach(c => codes.push(c));
      if (eff.cc && eff.cc.reason_codes) eff.cc.reason_codes.forEach(c => codes.push(c));
      const uniq = [];
      codes.forEach(c => { if (c && !uniq.includes(c)) uniq.push(c); });
      return uniq;
    }

    const kbReasonItems = computed(() => kbCollectReasonCodes().map(code => {
      const help = KB_REASON_HELP[code] || { title: code, advice: '参见设计文档 / 日志了解详情。' };
      return { code, title: help.title, advice: help.advice };
    }));

    function kbEffMode(policy) {
      const eff = kbStatus.value.effective || {};
      if (policy === 'scanner') return (eff.scanner && eff.scanner.mode) || '-';
      if (policy === 'cc') return (eff.cc && eff.cc.mode) || '-';
      return eff.global_mode || '-';
    }
    function kbEffReachable(policy) {
      const eff = kbStatus.value.effective || {};
      if (policy === 'scanner') return !!(eff.scanner && eff.scanner.install_reachable);
      if (policy === 'cc') return !!(eff.cc && eff.cc.install_reachable);
      return !!eff.global_install_reachable;
    }

    const ccAutoReady = computed(() => {
      const e = kbStatus.value.effective || {};
      return !!(e.cc && e.cc.auto_ready);
    });

    const kbChecklist = computed(() => {
      const c = kbStatus.value.configured || {};
      const m = kbStatus.value.migration || {};
      const ns = kbStatus.value.counter_namespace;
      const healthOk = kbStatus.value.health && kbStatus.value.health.state === 'ok';
      const hasRules = (c.cc_rule_ids && c.cc_rule_ids.length) || (kbStatus.value.cc_rules && kbStatus.value.cc_rules.length);
      return [
        { id: 'enabled', label: '全局已启用', ok: !!c.enabled },
        { id: 'observe_first', label: '功能已启用（建议先使用观察模式）', ok: !!c.enabled },
        { id: 'topology', label: 'topology=direct 已配置（enforce 安装必需）', ok: c.topology === 'direct' },
        { id: 'scope', label: '已配置受保护地址和端口', ok: (c.protected_addresses||[]).length > 0 && (c.protected_ports||[]).length > 0 },
        { id: 'helper', label: 'Helper 健康', ok: !!healthOk },
        { id: 'cc_rules', label: 'CC 规则 ID 已配置（如使用 CC）', ok: !!hasRules || c.cc_enabled === false },
        { id: 'migration', label: '频率 ID 迁移已完成', ok: m.status === 'completed' || m.status === 'no_rules' },
        { id: 'v2', label: 'v2 counter namespace 已切换', ok: ns === 'v2' || m.status === 'no_rules' },
        { id: 'cc_ready', label: 'CC enforce_ready 已确认（如需 CC 执行）', ok: !!c.cc_enforce_ready || c.cc_enabled === false, auto_ready: kbStatus.value.effective && kbStatus.value.effective.cc && kbStatus.value.effective.cc.auto_ready },
      ];
    });

    function formatKbTime(ts) {
      if (!ts) return '-';
      const d = new Date(ts * 1000);
      if (isNaN(d.getTime())) return String(ts);
      return d.toLocaleString();
    }
    function formatKbExpiry(ts) {
      if (!ts) return '-';
      const now = Math.floor(Date.now() / 1000);
      const left = ts - now;
      if (left <= 0) return '已过期';
      if (left < 60) return left + 's left';
      if (left < 3600) return Math.floor(left / 60) + 'm left';
      if (left < 86400) return Math.floor(left / 3600) + 'h left';
      return Math.floor(left / 86400) + 'd left';
    }
    function kbEvidenceSummary(c) {
      const e = (c && c.evidence) || {};
      const parts = [];
      if (e.block_hits != null) parts.push('blocks=' + e.block_hits);
      if (e.violation_count != null) parts.push('violations=' + e.violation_count);
      if (e.flagged != null) parts.push('flagged=' + String(e.flagged));
      if (e.strict != null) parts.push('strict=' + String(e.strict));
      if (e.reason) parts.push(e.reason);
      return parts.join(' ') || '-';
    }
    function kbSyncFormFromStatus() {
      if (kbFormDirty.value) return;
      const c = kbStatus.value.configured || {};
      kbForm.enabled = !!c.enabled;
      kbForm.mode = c.mode || 'observe';
      kbForm.topology = c.topology || 'unknown';
      kbForm.protected_addresses_str = (c.protected_addresses || []).join(', ');
      kbForm.protected_ports_str = (c.protected_ports || []).join(', ');
      kbForm.cc_enforce_ready = !!c.cc_enforce_ready;
      kbForm.scanner_enabled = c.scanner_enabled !== false;
      kbForm.cc_enabled = c.cc_enabled !== false;
    }
    function kbOpenDetail(entry) {
      kbDetail.entry = entry;
      kbDetail.show = true;
    }
    function kbReloadList() {
      if (kbTab.value === 'entries') loadKbEntries();
      else if (kbTab.value === 'candidates') loadKbCandidates();
    }


    const statusRow = computed(() => status.value);


    // ---- Bucket trend chart data ----
    const kbTrendPoints = computed(() => {
      const samples = kbBucketHistory.value;
      if (samples.length < 2) return { enforce: '', observe: '', max: 1, labels: [] };
      const max = Math.max(
        ...samples.map(s => Math.max(s.enforce_tokens || 0, s.observe_tokens || 0)),
        1
      );
      const w = 100 / (samples.length - 1);
      const toPts = (key) => samples.map((s, i) => {
        const v = s[key] || 0;
        return `${(i * w).toFixed(1)},${(100 - (v / max) * 100).toFixed(1)}`;
      }).join(' ');
      const labels = samples.map(s => {
        const d = new Date(s.t * 1000);
        return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
      });
      return { enforce: toPts('enforce_tokens'), observe: toPts('observe_tokens'), max, labels };
    });

    const kbTrendFillEnforce = computed(() => {
      const p = kbTrendPoints.value;
      if (!p.enforce) return '';
      return `0,100 ${p.enforce} 100,100`;
    });
    const kbTrendFillObserve = computed(() => {
      const p = kbTrendPoints.value;
      if (!p.observe) return '';
      return `0,100 ${p.observe} 100,100`;
    });

    const connLinePoints = computed(() => {
      const pts = connHistory.value;
      if (pts.length < 2) return '';
      const max = Math.max(...pts, 1);
      const w = 100 / (pts.length - 1);
      return pts.map((v, i) => `${(i * w).toFixed(1)},${(100 - (v / max) * 100).toFixed(1)}`).join(' ');
    });

    const connFillPoints = computed(() => {
      const pts = connHistory.value;
      if (pts.length < 2) return '';
      const max = Math.max(...pts, 1);
      const w = 100 / (pts.length - 1);
      const line = pts.map((v, i) => `${(i * w).toFixed(1)},${(100 - (v / max) * 100).toFixed(1)}`).join(' ');
      return `0,100 ` + line + ` 100,100`;
    });


    // ---- Kernel Blocking ----
    async function loadKbData() {
      kbError.value = '';
      const statusRequest = (async () => {
        try {
          const d = await api('GET', '/verynginx/kernel-blocking/status');
          if (d.ret === 'success') {
            kbStatus.value = Object.assign({}, kbStatus.value, d.data || {});
            kbSyncFormFromStatus();
          } else {
            kbError.value = d.message || '状态加载失败';
          }
        } catch (e) {
          kbError.value = e.message;
        }
      })();
      let tabRequest;
      if (kbTab.value === 'candidates') tabRequest = loadKbCandidates();
      else if (kbTab.value === 'timeline') tabRequest = loadKbTimeline();
      else if (kbTab.value === 'dashboard') tabRequest = loadKbDashboard();
      else tabRequest = loadKbEntries();
      await Promise.all([statusRequest, tabRequest]);
    }

    async function loadKbEntries(cursor) {
      const tok = gKbEntries.mark();
      try {
        let url = '/verynginx/kernel-blocking/entries?page_size=50';
        if (cursor) url += '&cursor=' + cursor;
        if (kbFilterPolicy.value) url += '&policy=' + encodeURIComponent(kbFilterPolicy.value);
        if (kbFilterIP.value) url += '&ip=' + encodeURIComponent(kbFilterIP.value);
        const d = await api('GET', url);
        if (!gKbEntries.isCurrent(tok)) return;
        if (d.ret === 'success') {
          kbEntriesCurrentCursor.value = cursor || null;
          if (!cursor) kbEntriesPrev.value = [];
          kbEntries.value = d.data.entries || [];
          kbEntriesNext.value = d.data.next_cursor;
        } else {
          kbError.value = d.message || '条目加载失败';
        }
      } catch (e) { if (gKbEntries.isCurrent(tok)) kbError.value = e.message; }
    }

    function kbEntriesPageNext() {
      if (!kbEntriesNext.value) return;
      kbEntriesPrev.value.push(kbEntriesCurrentCursor.value);
      loadKbEntries(kbEntriesNext.value);
    }

    function kbEntriesPagePrev() {
      const prev = kbEntriesPrev.value.pop();
      if (prev != null) loadKbEntries(prev);
    }

    async function loadKbCandidates(cursor) {
      const tok = gKbCandidates.mark();
      try {
        let url = '/verynginx/kernel-blocking/candidates?page_size=50';
        if (cursor) url += '&cursor=' + cursor;
        if (kbFilterState.value) url += '&state=' + encodeURIComponent(kbFilterState.value);
        if (kbFilterIP.value) url += '&ip=' + encodeURIComponent(kbFilterIP.value);
        const d = await api('GET', url);
        if (!gKbCandidates.isCurrent(tok)) return;
        if (d.ret === 'success') {
          kbCandidatesCurrentCursor.value = cursor || null;
          if (!cursor) kbCandidatesPrev.value = [];
          kbCandidates.value = d.data.entries || [];
          kbCandidatesNext.value = d.data.next_cursor;
        } else {
          kbError.value = d.message || '候选加载失败';
        }
      } catch (e) { if (gKbCandidates.isCurrent(tok)) kbError.value = e.message; }
    }

    function kbCandidatesPageNext() {
      if (!kbCandidatesNext.value) return;
      kbCandidatesPrev.value.push(kbCandidatesCurrentCursor.value);
      loadKbCandidates(kbCandidatesNext.value);
    }

    function kbCandidatesPagePrev() {
      const prev = kbCandidatesPrev.value.pop();
      if (prev != null) loadKbCandidates(prev);
    }

    async function loadKbTimeline() {
      const tok = gKbTimeline.mark();
      try {
        let url = '/verynginx/audit?limit=300';
        if (kbTimelineFilter.value) {
          // Specific action filter - exact match on server (full ring scan)
          url += '&action=kernel_blocking.' + encodeURIComponent(kbTimelineFilter.value);
        } else {
          // No filter: prefix match to get ALL kernel_blocking events from full ring (1000)
          url += '&action_prefix=kernel_blocking';
        }
        const d = await api('GET', url);
        if (!gKbTimeline.isCurrent(tok)) return;
        if (d.ret === 'success') {
          const all = d.data || [];
          kbTimeline.value = all;
        } else {
          kbError.value = d.message || '时间线加载失败';
        }
      } catch (e) { if (gKbTimeline.isCurrent(tok)) kbError.value = e.message; }
    }

    // Reload timeline when the filter changes while on the timeline tab
    watch(kbTimelineFilter, () => {
      if (page.value === 'kb' && kbTab.value === 'timeline') loadKbTimeline();
    });

    // Clear the dirty-form guard when leaving the KB page
    watch(page, (p) => {
      if (p !== 'kb') kbFormDirty.value = false;
    });

    function kbTimelineActionLabel(action) {
      const map = {
        'kernel_blocking.promote': '封禁',
        'kernel_blocking.clear': '解除',
        'kernel_blocking.reconcile': '协调',
        'kernel_blocking.lifecycle': '生命周期',
      };
      return map[action] || action || '-';
    }

    function kbTimelineActionClass(action) {
      if (action === 'kernel_blocking.promote') return 'tag-err';
      if (action === 'kernel_blocking.clear') return 'tag-ok';
      if (action === 'kernel_blocking.reconcile') return 'tag-info';
      return 'tag-warn';
    }

    async function loadKbBucketHistory() {
      const tok = gKbBucket.mark();
      kbBucketHistoryLoading.value = true;
      kbBucketHistoryError.value = '';
      try {
        const d = await api('GET', '/verynginx/kernel-blocking/bucket-history');
        if (!gKbBucket.isCurrent(tok)) return;
        if (d.ret === 'success') {
          kbBucketHistory.value = d.data.samples || [];
        } else {
          kbBucketHistoryError.value = d.message || '桶历史加载失败';
          kbBucketHistory.value = [];
        }
      } catch (e) {
        if (e.message !== 'session_expired' && gKbBucket.isCurrent(tok)) kbBucketHistoryError.value = e.message;
        if (gKbBucket.isCurrent(tok)) kbBucketHistory.value = [];
      } finally {
        if (gKbBucket.isCurrent(tok)) kbBucketHistoryLoading.value = false;
      }
    }

    async function loadKbDiff() {
      kbDiffError.value = '';
      try {
        const d = await api('GET', '/verynginx/kernel-blocking/diff');
        if (d.ret === 'success') kbDiff.value = d.data || kbDiff.value;
        else kbDiffError.value = d.message || '差异加载失败';
      } catch (e) {
        if (e.message !== 'session_expired') kbDiffError.value = e.message;
      }
    }

    async function loadKbDashboard() {
      await Promise.all([loadKbBucketHistory(), loadKbDiff()]);
    }

    async function enableCcEnforceReady() {
      if (!await showConfirm({
        title: '启用 CC enforce_ready',
        message: '启用 CC enforce_ready? 这将为符合条件的 IP 激活自动 CC 内核封禁。',
        type: 'danger',
        requireInput: true,
        inputLabel: '请输入 "ENABLE" 确认',
        inputExpected: 'ENABLE',
      })) return;
      kbBusy.value = true;
      try {
        const full = await api('GET', '/verynginx/config');
        if (!full || typeof full !== 'object') throw new Error('config load failed');
        const kb = Object.assign({}, full.kernel_ip_blocking || {});
        kb.cc = Object.assign({}, kb.cc || {}, { enforce_ready: true });
        full.kernel_ip_blocking = kb;
        const d = await api('POST', '/verynginx/config', full);
        if (d.ret === 'success') {
          showToast('CC enforce_ready enabled — CC auto-promotion active', 'success');
          if (shared.cfg) shared.cfg.value = full;
          await loadKbData();
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbSaveSettings() {
      // Validate protected ports/addresses client-side. The schema only WARNs,
      // and a bad port reaches the firewall helper and explodes there. Catch it
      // here with a clear message instead.
      const ports = kbForm.protected_ports_str.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
      for (const p of ports) {
        const n = Number(p);
        if (!Number.isInteger(n) || n < 1 || n > 65535) {
          showToast('受保护端口无效 (1-65535): ' + p, 'error'); return;
        }
      }
      const addrs = kbForm.protected_addresses_str.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
      for (const a of addrs) {
        if (!isValidIpLiteral(a, true)) {
          showToast('受保护地址无效 (IP/CIDR): ' + a, 'error'); return;
        }
      }
      if (kbForm.mode === 'enforce' && !kbForm.enabled) {
        showToast('启用执行模式前必须先启用全局开关', 'error'); return;
      }
      if (kbForm.mode === 'enforce' && !await showConfirm({
        title: '保存执行模式设置',
        message: '切换/保存执行相关设置? 请确保 Helper、拓扑和检查清单已就绪。',
        type: 'warning',
      })) return;
      if (kbForm.cc_enforce_ready && !await showConfirm({
        title: '启用 CC enforce_ready',
        message: '确认迁移/切换/校准完成后启用 CC enforce_ready=true？',
        type: 'danger',
      })) return;
      kbBusy.value = true;
      try {
        const full = await api('GET', '/verynginx/config');
        if (!full || typeof full !== 'object') throw new Error('config load failed');
        const kb = Object.assign({}, full.kernel_ip_blocking || {});
        kb.enabled = !!kbForm.enabled;
        kb.mode = kbForm.mode;
        kb.topology = kbForm.topology || 'unknown';
        kb.protected_addresses = kbForm.protected_addresses_str.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
        kb.protected_ports = kbForm.protected_ports_str.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
        kb.scanner = Object.assign({}, kb.scanner || {}, { enabled: !!kbForm.scanner_enabled });
        kb.cc = Object.assign({}, kb.cc || {}, {
          enabled: !!kbForm.cc_enabled,
          enforce_ready: !!kbForm.cc_enforce_ready,
        });
        full.kernel_ip_blocking = kb;
        const d = await api('POST', '/verynginx/config', full);
        if (d.ret === 'success') {
          showToast('内核锁阻设置已保存', 'success');
          if (shared.cfg) shared.cfg.value = full;
          kbFormDirty.value = false;
          await loadKbData();
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbPromote() {
      if (!kbNewIP.value) { showToast('请输入 IP', 'error'); return; }
      // Client-side IP format validation (IPv4/IPv6 literal)
      const ip = kbNewIP.value.trim();
      if (!isValidIpLiteral(ip, false)) { showToast('IP 格式无效: ' + ip, 'error'); return; }
      // An empty/zero TTL would be coerced server-side to 86400s (24h). Default
      // to a safe short TTL instead of silently amplifying the block window.
      const ttlNum = Number(kbNewTTL.value);
      const ttl = (ttlNum && ttlNum > 0) ? ttlNum : 300;
      if (!await showConfirm({ title: '手动封禁 IP', message: `手动封禁 ${ip} 策略 ${kbNewPolicy.value} TTL ${ttl}秒?`, type: 'danger' })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/promote', {
          ip, policy: kbNewPolicy.value, ttl: ttl
        });
        if (d.ret === 'success') {
          showToast('IP ' + ip + ' blocked', 'success');
          kbNewIP.value = '';
          await loadKbData();
        } else {
          showToast(d.message || 'Promote failed', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbPromoteIp(ip, policy) {
      if (!isValidIpLiteral(ip || '', false)) { showToast('IP 格式无效: ' + (ip || ''), 'error'); return; }
      if (!await showConfirm({ title: '晋升 IP', message: `晋升 ${ip} 为 ${policy} (TTL 300秒)?`, type: 'danger' })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/promote', { ip, policy, ttl: 300 });
        if (d.ret === 'success') {
          showToast('IP ' + ip + ' 已晋升', 'success');
          await loadKbData();
        } else {
          showToast(d.message || '晋升失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbReconcile() {
      if (!await showConfirm({ title: '触发协调', message: '立即触发协调?', type: 'primary' })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/reconcile', {});
        if (d.ret === 'success') {
          const r = d.data || {};
          showToast('协调完成: 添加=' + ((r.to_add&&r.to_add.length)||r.applied_add||0) + ' 移除=' + ((r.to_remove&&r.to_remove.length)||r.applied_remove||0), 'success');
          await loadKbData();
        } else {
          showToast(d.message || '协调失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbClear(ip) {
      if (!isValidIpLiteral(ip || '', false)) { showToast('IP 格式无效: ' + (ip || ''), 'error'); return; }
      if (!await showConfirm({ title: '清除封禁条目', message: `清除 ${ip} 的所有内核封禁条目?`, type: 'danger' })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/clear', { ip });
        if (d.ret === 'success') {
          showToast('IP ' + ip + ' cleared', 'success');
          await loadKbData();
        } else {
          showToast(d.message || 'Clear failed', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbPause(paused) {
      if (!await showConfirm({ title: paused ? '暂停自动晋升' : '恢复自动晋升', message: paused ? '暂停自动晋升?' : '恢复自动晋升?', type: 'warning' })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/pause', { paused });
        if (d.ret === 'success') {
          showToast(paused ? '晋升已暂停' : '晋升已恢复', 'success');
          await loadKbData();
        } else {
          showToast(d.message || '暂停失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbFlushAuto() {
      if (!await showConfirm({
        title: '刷新自动条目',
        message: '刷新所有自动扫描器/cc 内核条目? 此操作不可撤销。',
        type: 'danger',
      })) return;
      if (!await showConfirm({
        title: '最终确认',
        message: '最终确认: 立即刷新自动集合?',
        type: 'danger',
        requireInput: true,
        inputLabel: '请输入 "FLUSH" 确认',
        inputExpected: 'FLUSH',
      })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/flush-auto');
        if (d.ret === 'success') {
          showToast('已清理自动条目 (' + ((d.data && d.data.removed) || 0) + ')', 'success');
          await loadKbData();
        } else {
          showToast(d.message || 'Flush failed', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    // ---- Exports ----
    view('kbStatus', kbStatus);
    view('kbEntries', kbEntries);
    const kbEntriesTbl = shared.createTableTools(kbEntries);
    view('kbEntriesTbl', kbEntriesTbl);
    view('kbCandidates', kbCandidates);
    const kbCandidatesTbl = shared.createTableTools(kbCandidates);
    view('kbCandidatesTbl', kbCandidatesTbl);
    view('kbTimeline', kbTimeline);
    const kbTimelineTbl = shared.createTableTools(kbTimeline);
    view('kbTimelineTbl', kbTimelineTbl);
    view('kbTimelineFilter', kbTimelineFilter);
    view('kbEntriesNext', kbEntriesNext);
    view('kbCandidatesNext', kbCandidatesNext);
    view('kbEntriesPrev', kbEntriesPrev);
    view('kbCandidatesPrev', kbCandidatesPrev);
    ctx('kbBucketHistory', kbBucketHistory);
    view('kbBucketHistoryLoading', kbBucketHistoryLoading);
    view('kbBucketHistoryError', kbBucketHistoryError);
    view('kbDiff', kbDiff);
    view('kbDiffError', kbDiffError);
    view('kbTab', kbTab);
    view('kbNewIP', kbNewIP);
    view('kbNewPolicy', kbNewPolicy);
    view('kbNewTTL', kbNewTTL);
    view('kbError', kbError);
    view('kbBusy', kbBusy);
    view('kbFilterPolicy', kbFilterPolicy);
    view('kbFilterState', kbFilterState);
    view('kbFilterIP', kbFilterIP);
    view('kbForm', kbForm);
    view('kbDetail', kbDetail);
    view('kbDetailJson', kbDetailJson);
    ctx('kbFormDirty', kbFormDirty);
    view('kbMarkFormDirty', kbMarkFormDirty);
    view('kbReasonItems', kbReasonItems);
    view('kbEffMode', kbEffMode);
    view('kbEffReachable', kbEffReachable);
    view('ccAutoReady', ccAutoReady);
    view('kbChecklist', kbChecklist);
    view('formatKbTime', formatKbTime);
    view('formatKbExpiry', formatKbExpiry);
    view('kbEvidenceSummary', kbEvidenceSummary);
    view('kbOpenDetail', kbOpenDetail);
    view('kbReloadList', kbReloadList);
    view('statusRow', statusRow);
    view('kbTrendPoints', kbTrendPoints);
    view('kbTrendFillEnforce', kbTrendFillEnforce);
    view('kbTrendFillObserve', kbTrendFillObserve);
    view('connLinePoints', connLinePoints);
    view('connFillPoints', connFillPoints);
    view('loadKbData', loadKbData);
    view('loadKbEntries', loadKbEntries);
    view('kbEntriesPageNext', kbEntriesPageNext);
    view('kbEntriesPagePrev', kbEntriesPagePrev);
    view('loadKbCandidates', loadKbCandidates);
    view('kbCandidatesPageNext', kbCandidatesPageNext);
    view('kbCandidatesPagePrev', kbCandidatesPagePrev);
    view('loadKbTimeline', loadKbTimeline);
    view('kbTimelineActionLabel', kbTimelineActionLabel);
    view('kbTimelineActionClass', kbTimelineActionClass);
    view('loadKbBucketHistory', loadKbBucketHistory);
    view('loadKbDashboard', loadKbDashboard);
    view('enableCcEnforceReady', enableCcEnforceReady);
    view('kbSaveSettings', kbSaveSettings);
    view('kbPromote', kbPromote);
    view('kbPromoteIp', kbPromoteIp);
    view('kbReconcile', kbReconcile);
    view('kbClear', kbClear);
    view('kbPause', kbPause);
    view('kbFlushAuto', kbFlushAuto);
    view('expandedCcRules', expandedCcRules);
    view('toggleCcRule', toggleCcRule);

    // Wipe per-session kernel-blocking data on logout. kbStatus (global
    // policy/config) is intentionally left for the next load to refresh.
    // Keyboard: Esc close + focus management for all dialogs.
    shared.bindModal(kbDetail);

    shared.onLogout(() => {
      kbEntries.value = [];
      kbCandidates.value = [];
      kbTimeline.value = [];
      kbDiff.value = { missing_in_kernel: [], orphan_in_kernel: [], desired_count: 0, actual_count: 0 };
      kbBucketHistory.value = [];
      kbEntriesNext.value = null;
      kbCandidatesNext.value = null;
      kbEntriesPrev.value = [];
      kbCandidatesPrev.value = [];
      kbEntriesCurrentCursor.value = null;
      kbCandidatesCurrentCursor.value = null;
      kbDetail.show = false;
      kbDetail.entry = null;
      expandedCcRules.clear();
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();