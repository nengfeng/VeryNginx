
const { reactive, ref, computed, watch } = Vue;

// Module-level store so api() can access it for session expiration handling
let store = reactive({ loggedIn: false, user: null });

// ---- API ----
let csrfToken = null;

// Strict IP literal validation (IPv4 0-255 per octet, IPv6 with optional /prefix).
// Mirrors api/helpers.lua is_valid_ip semantics on the client side.
function isValidIpLiteral(ip, allowPrefix) {
  if (!ip || typeof ip !== 'string') return false;
  const s = ip.trim();
  if (!s) return false;
  if (s.includes(':')) {
    // IPv6 literal (optionally with /<prefix>)
    const body = allowPrefix ? s.split('/')[0] : s;
    if (!/^[0-9a-fA-F:]+$/.test(body) || !body.includes(':')) return false;
    if (allowPrefix && s.includes('/')) {
      const p = Number(s.split('/')[1]);
      if (!Number.isInteger(p) || p < 0 || p > 128) return false;
    }
    return true;
  }
  // IPv4 literal (optionally with /<prefix>)
  const body = allowPrefix ? s.split('/')[0] : s;
  const parts = body.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255) return false;
    if (p.length > 1 && p[0] === '0') return false; // no leading zeros
  }
  if (allowPrefix && s.includes('/')) {
    const p = Number(s.split('/')[1]);
    if (!Number.isInteger(p) || p < 0 || p > 32) return false;
  }
  return true;
}

// Session-expired errors are raised by api() on 401/403 and already
// handled centrally (store.loggedIn=false → login page). Swallow them at
// the global level so timer-driven refreshes (loadStatus every 3s, etc.)
// don't produce unhandled Promise rejections / console noise.
window.addEventListener('unhandledrejection', (ev) => {
  const reason = ev && ev.reason;
  if (reason && reason.message === 'session_expired') {
    ev.preventDefault();
  }
});

async function api(method, path, body, opts2) {
  const opts = { method, credentials: 'same-origin' };
  if (body) {
    if (body instanceof URLSearchParams) {
      opts.body = body;
    } else if (typeof body === 'object' && !(body instanceof FormData)) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    } else {
      opts.body = body;
    }
  }
  if (method !== 'GET') {
    if (csrfBroken) {
      // Last CSRF refresh failed; try once more before blocking. If the
      // token was only transiently stale this recovers without a reload.
      try {
        const d = await fetch('/verynginx/csrf', { method: 'GET', credentials: 'same-origin' });
        if (d.ok) {
          const j = await d.json();
          csrfToken = j.csrf_token;
          csrfBroken = false;
        } else if (d.status === 401 || d.status === 403) {
          // Session actually expired — surface as session_expired so the
          // central handler logs out and redirects to login.
          csrfToken = null;
          csrfBroken = false;
          if (typeof store !== 'undefined') {
            store.loggedIn = false;
            store.user = null;
          }
          throw new Error('session_expired');
        }
      } catch (e) {
        if (e.message === 'session_expired') throw e;
        /* keep broken for transient failures */
      }
    }
    if (csrfBroken) {
      throw new Error('CSRF 令牌刷新失败，请刷新页面后重试');
    }
    if (csrfToken) {
      opts.headers = opts.headers || {};
      opts.headers['X-CSRF-Token'] = csrfToken;
    }
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    // Session expired or unauthorized — redirect to login
    if (res.status === 401 || res.status === 403) {
      csrfToken = null;
      if (typeof store !== 'undefined') {
        store.loggedIn = false;
        store.user = null;
      }
      throw new Error('session_expired');
    }
    const text = await res.text().catch(() => '');
    let msg;
    try { const j = JSON.parse(text); msg = j.message || j.err || text; } catch { msg = text || `HTTP ${res.status}`; }
    throw new Error(msg);
  }
  if (opts2 && opts2.text) return res.text();
  return res.json();
}

let csrfBroken = false;

async function refreshCsrf() {
  try {
    const d = await api('GET', '/verynginx/csrf');
    csrfToken = d.csrf_token;
    csrfBroken = false;
  } catch (e) {
    console.warn('CSRF token refresh failed:', e.message);
    if (e.message !== 'session_expired') csrfBroken = true;
  }
}

// ---- App ----
// Dark mode toggle (before app mount)
;(function() {
  try {
    var saved = localStorage.getItem('vn_theme');
    if (saved === 'dark' || (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  } catch(e) {}
})();

const app = Vue.createApp({
  setup() {
    const exports = new Map();
    function expose(name, value) { exports.set(name, value); }
    // Expose module-level store for template access
    expose('store', store);
    const page = ref('dashboard');
        expose('page', page);
    const dashTab = ref('overview');
        expose('dashTab', dashTab);
    const advTab = ref('fingerprints');
        expose('advTab', advTab);
    const loading = ref(false);
        expose('loading', loading);
    const loginUser = ref('');
        expose('loginUser', loginUser);
    const loginPass = ref('');
        expose('loginPass', loginPass);
    const loginError = ref('');
        expose('loginError', loginError);
    const status = ref({});
        expose('status', status);
    const connHistory = ref([]);
        expose('connHistory', connHistory);
    const cfg = ref({});
        expose('cfg', cfg);
    const healthData = ref({});
        expose('healthData', healthData);
    const overview = ref({});
        expose('overview', overview);
    const dictUsage = ref([]);
        expose('dictUsage', dictUsage);
     const cfgTab = ref('system');
         expose('cfgTab', cfgTab);
     const theme = ref(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
         expose('theme', theme);

     function toggleTheme() {
         expose('toggleTheme', toggleTheme);
       const newTheme = theme.value === 'dark' ? 'light' : 'dark';
       theme.value = newTheme;
       document.documentElement.setAttribute('data-theme', newTheme);
       try { localStorage.setItem('vn_theme', newTheme); } catch(e) {}
     }
    const rawJson = ref('');
        expose('rawJson', rawJson);
    const jsonError = ref('');
        expose('jsonError', jsonError);
    watch(rawJson, (val) => {
      jsonError.value = '';
      if (!val) return;
      try { JSON.parse(val); } catch (e) { jsonError.value = 'JSON: ' + e.message; }
    });
    const jsonSaving = ref(false);
        expose('jsonSaving', jsonSaving);
    const statsData = ref(null);
        expose('statsData', statsData);
    const statsType = ref('long');
        expose('statsType', statsType);
    const statsError = ref('');
        expose('statsError', statsError);
    const expandedUri = ref(null);
        expose('expandedUri', expandedUri);
    const editMatcherModal = reactive({ show: false, name: '', conditions: '' });
        expose('editMatcherModal', editMatcherModal);

    // ---- Config Rule Editor State ----
    const ruleEditModal = reactive({
      show: false, mode: 'create', _group: '', _index: -1,
      enable: true, matcherType: 'inline', matcherJson: '{}',
      action: 'block', code: 403, to_uri: '', upstream: '',
      root: '', path: '', expires: '', response: '',
    });
        expose('ruleEditModal', ruleEditModal);
    const ruleSaving = ref(false);
        expose('ruleSaving', ruleSaving);
    const upstreamKeys = computed(() => Object.keys(cfg.value.backend_upstream || {}).sort());
        expose('upstreamKeys', upstreamKeys);

    // ---- WAF State ----
    const wafTab = ref('rules');
        expose('wafTab', wafTab);
    const wafRuleView = ref('list');
        expose('wafRuleView', wafRuleView);
    const wafAttackView = ref('stats');
        expose('wafAttackView', wafAttackView);
    const wafError = ref('');
        expose('wafError', wafError);
    const wafRules = ref([]);
        expose('wafRules', wafRules);
    const wafCategories = ref({});
        expose('wafCategories', wafCategories);
    const wafPagination = reactive({ page: 1, limit: 20, total: 0, total_pages: 0 });
        expose('wafPagination', wafPagination);
    const wafFilterCat = ref('');
        expose('wafFilterCat', wafFilterCat);
    const wafFilterSev = ref('');
        expose('wafFilterSev', wafFilterSev);
    const wafStatsData = ref(null);
        expose('wafStatsData', wafStatsData);
    const wafStatsError = ref('');
        expose('wafStatsError', wafStatsError);
    const wafHistory = ref([]);
        expose('wafHistory', wafHistory);
    const wafHistError = ref('');
        expose('wafHistError', wafHistError);
    const wafRolling = ref(false);
        expose('wafRolling', wafRolling);
    const wafToggleBusy = ref(false);
        expose('wafToggleBusy', wafToggleBusy);
    const wafDeleteBusy = ref(false);
        expose('wafDeleteBusy', wafDeleteBusy);
    const wafEditModal = reactive({
      show: false, mode: 'create',
      id: '', name: '', description: '', category: '', severity: '',
      action: 'block', code: 403, matcherJson: '{}',
      tagsStr: '',
      rateLimitEnabled: false, rateLimitMax: 10, rateLimitWindow: 60, rateLimitAction: 'log'
    });
        expose('wafEditModal', wafEditModal);
    const wafEditError = ref('');
        expose('wafEditError', wafEditError);
    const wafSaving = ref(false);
        expose('wafSaving', wafSaving);
    const wafTestRuleJson = ref('');
        expose('wafTestRuleJson', wafTestRuleJson);
    const wafTestCasesJson = ref('');
        expose('wafTestCasesJson', wafTestCasesJson);
    const wafTestError = ref('');
        expose('wafTestError', wafTestError);
    const wafTesting = ref(false);
        expose('wafTesting', wafTesting);
    const wafTestResults = ref(null);
        expose('wafTestResults', wafTestResults);
    const wafHits = ref([]);
        expose('wafHits', wafHits);
    const wafHitsError = ref('');
        expose('wafHitsError', wafHitsError);
    const wafHitsTime = ref('');
        expose('wafHitsTime', wafHitsTime);
    const wafHitsLimit = ref(50);
        expose('wafHitsLimit', wafHitsLimit);
    const wafAnalytics = ref({ rules: [], dead_rules: [] });
        expose('wafAnalytics', wafAnalytics);
    const wafAnalyticsLoading = ref(false);
        expose('wafAnalyticsLoading', wafAnalyticsLoading);
    const wafAnalyticsError = ref('');
        expose('wafAnalyticsError', wafAnalyticsError);
    const wafPendingChanges = ref([]);
        expose('wafPendingChanges', wafPendingChanges);
    const wafTimeline = ref({ buckets: [], categories: [], bucket_minutes: 5, hours: 1 });
        expose('wafTimeline', wafTimeline);
    const wafTimelineHours = ref(1);
        expose('wafTimelineHours', wafTimelineHours);
    const wafTimelineBucket = ref(5);
        expose('wafTimelineBucket', wafTimelineBucket);
    const wafTimelineLoading = ref(false);
        expose('wafTimelineLoading', wafTimelineLoading);
    const wafTimelineError = ref('');
        expose('wafTimelineError', wafTimelineError);
    const wafTestHistory = ref([]);
        expose('wafTestHistory', wafTestHistory);
    const wafHitDetailModal = reactive({ show: false, loading: false, data: null, error: '' });
        expose('wafHitDetailModal', wafHitDetailModal);
    const wafIpHits = ref([]);
        expose('wafIpHits', wafIpHits);
    const wafIpHitsIp = ref('');
        expose('wafIpHitsIp', wafIpHitsIp);

    // Unified confirm modal
    const confirmModal = reactive({
      show: false,
      title: '',
      message: '',
      type: 'danger',
      requireInput: false,
      inputLabel: '',
      inputValue: '',
      inputExpected: '',
      resolve: null,
      reject: null,
    });
        expose('confirmModal', confirmModal);

    function showConfirm({ title, message, type = 'danger', requireInput = false, inputLabel = '', inputExpected = '' }) {
        expose('showConfirm', showConfirm);
      return new Promise((resolve, reject) => {
        confirmModal.show = true;
        confirmModal.title = title;
        confirmModal.message = message;
        confirmModal.type = type;
        confirmModal.requireInput = requireInput;
        confirmModal.inputLabel = inputLabel;
        confirmModal.inputValue = '';
        confirmModal.inputExpected = inputExpected;
        confirmModal.resolve = resolve;
        confirmModal.reject = reject;
      });
    }

    function confirmModalOk() {
        expose('confirmModalOk', confirmModalOk);
      if (confirmModal.requireInput) {
        if (confirmModal.inputValue.trim() !== confirmModal.inputExpected.trim()) {
          showToast('确认文本不匹配', 'error');
          return;
        }
      }
      confirmModal.show = false;
      confirmModal.resolve(true);
    }

    function confirmModalCancel() {
        expose('confirmModalCancel', confirmModalCancel);
      confirmModal.show = false;
      confirmModal.resolve(false);
    }

    // Watcher to ensure Promise always resolves if modal closes unexpectedly
    watch(() => confirmModal.show, (show) => {
      if (!show && confirmModal.resolve) {
        confirmModal.resolve(false);
      }
    });

    const freqStats = ref([]);
        expose('freqStats', freqStats);
    const freqRules = ref([]);
        expose('freqRules', freqRules);
    const freqTemplates = ref([]);
        expose('freqTemplates', freqTemplates);
    const freqTemplatesLoaded = ref(false);
        expose('freqTemplatesLoaded', freqTemplatesLoaded);
    const freqError = ref('');
        expose('freqError', freqError);
    const freqRuleModal = reactive({ show: false, mode: 'create', _matcherRef: null, id: '', key: 'ip', limit: 60, window: 60, code: 429, enable: true, matcherJson: '{}' });
        expose('freqRuleModal', freqRuleModal);
    const freqTemplateModal = reactive({ show: false, name: '', label: '', description: '', id: '', key: 'ip', limit: 60, window: 60, code: 429, matcherJson: '{}' });
        expose('freqTemplateModal', freqTemplateModal);
    const geoipLookupIP = ref('');
        expose('geoipLookupIP', geoipLookupIP);
    const geoipLookupResult = ref(null);
        expose('geoipLookupResult', geoipLookupResult);
    const geoipStats = ref([]);
        expose('geoipStats', geoipStats);
    const geoipMaxCount = computed(() => (geoipStats.value.length ? geoipStats.value[0].count : 0));
        expose('geoipMaxCount', geoipMaxCount);
    const geoipConfig = ref({ enable: false, geodb_path: '', whitelistStr: '', blocklistStr: '', auto_update: true, update_interval_hours: 168, mirror: 'auto', custom_mirror_url: '', license_key: '' });
        expose('geoipConfig', geoipConfig);
    const geoipStatus = ref({ available: false, size: 0, last_check: 0, last_update: 0, geodb_path: '' });
        expose('geoipStatus', geoipStatus);
    const geoipLoading = ref(false);
        expose('geoipLoading', geoipLoading);
    const geoipError = ref('');
        expose('geoipError', geoipError);
    const fingerprints = ref([]);
        expose('fingerprints', fingerprints);
    const fpCategories = ref({});
        expose('fpCategories', fpCategories);
    const fpError = ref('');
        expose('fpError', fpError);
    const fpToggleBusy = ref(false);
        expose('fpToggleBusy', fpToggleBusy);
    const fpEditModal = reactive({ show: false, hash: '', name: '', category: 'scanner', action: 'block' });
        expose('fpEditModal', fpEditModal);

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

    // ---- Audit State ----
    const auditEntries = ref([]);
        expose('auditEntries', auditEntries);
    const auditError = ref('');
        expose('auditError', auditError);
    const auditFilterUser = ref('');
        expose('auditFilterUser', auditFilterUser);
    const auditFilterAction = ref('');
        expose('auditFilterAction', auditFilterAction);
    const auditFilterSince = ref('');
        expose('auditFilterSince', auditFilterSince);
    const auditFilterUntil = ref('');
        expose('auditFilterUntil', auditFilterUntil);

    const plugins = ref([]);
        expose('plugins', plugins);
    const pluginsError = ref('');
        expose('pluginsError', pluginsError);
    const versionInfo = ref({ version: '', commit: '' });
        expose('versionInfo', versionInfo);
    const toastMsg = ref('');
        expose('toastMsg', toastMsg);
    const toastType = ref('info');
        expose('toastType', toastType);
    const toastVisible = ref(false);
        expose('toastVisible', toastVisible);
    let toastTimer = null;
    function showToast(msg, type) {
        expose('showToast', showToast);
      toastMsg.value = msg;
      toastType.value = type || 'info';
      toastVisible.value = true;
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toastVisible.value = false; }, 2500);
    }
    const configImportError = ref('');
        expose('configImportError', configImportError);
    const configImportOk = ref('');
        expose('configImportOk', configImportOk);
    const topPaths = ref([]);
        expose('topPaths', topPaths);

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
        expose('kbStatus', kbStatus);
    const kbEntries = ref([]);
        expose('kbEntries', kbEntries);
    const kbCandidates = ref([]);
        expose('kbCandidates', kbCandidates);
    const kbTimeline = ref([]);
        expose('kbTimeline', kbTimeline);
    const kbTimelineFilter = ref('');
        expose('kbTimelineFilter', kbTimelineFilter);
    const kbEntriesNext = ref(null);
        expose('kbEntriesNext', kbEntriesNext);
    const kbCandidatesNext = ref(null);
        expose('kbCandidatesNext', kbCandidatesNext);
    const kbEntriesPrev = ref([]);
        expose('kbEntriesPrev', kbEntriesPrev);
    const kbCandidatesPrev = ref([]);
        expose('kbCandidatesPrev', kbCandidatesPrev);
    const kbEntriesCurrentCursor = ref(null);
    const kbCandidatesCurrentCursor = ref(null);
    const kbBucketHistory = ref([]);
        expose('kbBucketHistory', kbBucketHistory);
    const kbBucketHistoryLoading = ref(false);
        expose('kbBucketHistoryLoading', kbBucketHistoryLoading);
    const kbBucketHistoryError = ref('');
        expose('kbBucketHistoryError', kbBucketHistoryError);
    const kbDiff = ref({ missing_in_kernel: [], orphan_in_kernel: [], desired_count: 0, actual_count: 0 });
        expose('kbDiff', kbDiff);
    const kbTab = ref('entries');
        expose('kbTab', kbTab);
    const kbNewIP = ref('');
        expose('kbNewIP', kbNewIP);
    const kbNewPolicy = ref('scanner');
        expose('kbNewPolicy', kbNewPolicy);
    const kbNewTTL = ref(300);
        expose('kbNewTTL', kbNewTTL);
    const kbError = ref('');
        expose('kbError', kbError);
    const kbBusy = ref(false);
        expose('kbBusy', kbBusy);
    const kbFilterPolicy = ref('');
        expose('kbFilterPolicy', kbFilterPolicy);
    const kbFilterState = ref('');
        expose('kbFilterState', kbFilterState);
    const kbFilterIP = ref('');
        expose('kbFilterIP', kbFilterIP);
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
        expose('kbForm', kbForm);
    const kbDetail = reactive({ show: false, entry: null });
        expose('kbDetail', kbDetail);
    const kbDetailJson = computed(() => kbDetail.entry ? JSON.stringify(kbDetail.entry, null, 2) : '');
        expose('kbDetailJson', kbDetailJson);
    const kbFormDirty = ref(false);
    function kbMarkFormDirty() { kbFormDirty.value = true; }
        expose('kbMarkFormDirty', kbMarkFormDirty);

    // Navigation guard for KB dirty form
    async function navigateTo(newPage) {
        expose('navigateTo', navigateTo);
      if (page.value === 'kb' && kbFormDirty.value) {
        if (!await showConfirm({
          title: '未保存的更改',
          message: 'KB 表单有未保存的更改，确定离开？',
          type: 'warning',
        })) return;
      }
      page.value = newPage;
      // Load data based on page
      if (newPage === 'waf') await loadWafData();
      else if (newPage === 'frequency') await loadFrequencyData();
      else if (newPage === 'reputation') await loadRepData();
      else if (newPage === 'geoip') { await loadGeoIP(); await loadGeoIPStatus(); }
      else if (newPage === 'kb') await loadKbData();
    }

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
        expose('kbReasonItems', kbReasonItems);

    function kbEffMode(policy) {
        expose('kbEffMode', kbEffMode);
      const eff = kbStatus.value.effective || {};
      if (policy === 'scanner') return (eff.scanner && eff.scanner.mode) || '-';
      if (policy === 'cc') return (eff.cc && eff.cc.mode) || '-';
      return eff.global_mode || '-';
    }
    function kbEffReachable(policy) {
        expose('kbEffReachable', kbEffReachable);
      const eff = kbStatus.value.effective || {};
      if (policy === 'scanner') return !!(eff.scanner && eff.scanner.install_reachable);
      if (policy === 'cc') return !!(eff.cc && eff.cc.install_reachable);
      return !!eff.global_install_reachable;
    }

    const ccAutoReady = computed(() => {
      const e = kbStatus.value.effective || {};
      return !!(e.cc && e.cc.auto_ready);
    });
        expose('ccAutoReady', ccAutoReady);

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
        expose('kbChecklist', kbChecklist);

    function formatKbTime(ts) {
        expose('formatKbTime', formatKbTime);
      if (!ts) return '-';
      const d = new Date(ts * 1000);
      if (isNaN(d.getTime())) return String(ts);
      return d.toLocaleString();
    }
    function formatKbExpiry(ts) {
        expose('formatKbExpiry', formatKbExpiry);
      if (!ts) return '-';
      const now = Math.floor(Date.now() / 1000);
      const left = ts - now;
      if (left <= 0) return 'expired';
      if (left < 60) return left + 's left';
      if (left < 3600) return Math.floor(left / 60) + 'm left';
      if (left < 86400) return Math.floor(left / 3600) + 'h left';
      return Math.floor(left / 86400) + 'd left';
    }
    function kbEvidenceSummary(c) {
        expose('kbEvidenceSummary', kbEvidenceSummary);
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
        expose('kbOpenDetail', kbOpenDetail);
      kbDetail.entry = entry;
      kbDetail.show = true;
    }
    function kbReloadList() {
        expose('kbReloadList', kbReloadList);
      if (kbTab.value === 'entries') loadKbEntries();
      else if (kbTab.value === 'candidates') loadKbCandidates();
    }


    const s = computed(() => status.value);
        expose('s', s);

    // ---- Bucket trend chart data (Design §12.2) ----
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
        expose('kbTrendPoints', kbTrendPoints);

    const kbTrendFillEnforce = computed(() => {
      const p = kbTrendPoints.value;
      if (!p.enforce) return '';
      return `0,100 ${p.enforce} 100,100`;
    });
        expose('kbTrendFillEnforce', kbTrendFillEnforce);
    const kbTrendFillObserve = computed(() => {
      const p = kbTrendPoints.value;
      if (!p.observe) return '';
      return `0,100 ${p.observe} 100,100`;
    });
        expose('kbTrendFillObserve', kbTrendFillObserve);

    const connLinePoints = computed(() => {
      const pts = connHistory.value;
      if (pts.length < 2) return '';
      const max = Math.max(...pts, 1);
      const w = 100 / (pts.length - 1);
      return pts.map((v, i) => `${(i * w).toFixed(1)},${(100 - (v / max) * 100).toFixed(1)}`).join(' ');
    });
        expose('connLinePoints', connLinePoints);

    const connFillPoints = computed(() => {
      const pts = connHistory.value;
      if (pts.length < 2) return '';
      const max = Math.max(...pts, 1);
      const w = 100 / (pts.length - 1);
      const line = pts.map((v, i) => `${(i * w).toFixed(1)},${(100 - (v / max) * 100).toFixed(1)}`).join(' ');
      return `0,100 ` + line + ` 100,100`;
    });
        expose('connFillPoints', connFillPoints);

    // ---- Auto-login on page load (check existing session cookie) ----
    async function checkSession() {
      try {
        const d = await api('GET', '/verynginx/csrf');
        csrfToken = d.csrf_token;
        store.loggedIn = true;
        store.user = 'verynginx';
        await loadData();
        if (page.value === 'dashboard' && dashTab.value === 'status') startStatusRefresh();
        if (page.value === 'dashboard' && dashTab.value === 'overview') loadOverview();
      } catch (e) {
        console.warn('Session check failed:', e.message);
      }
    }
    checkSession();
    loadVersion();

    // ---- Login ----
    async function doLogin() {
        expose('doLogin', doLogin);
      loginError.value = '';
      if (!loginUser.value || !loginPass.value) { loginError.value = '请输入用户名和密码。'; return; }
      loading.value = true;
      try {
        const params = new URLSearchParams();
        params.append('user', loginUser.value);
        params.append('password', loginPass.value);
        const d = await api('POST', '/verynginx/login', params);
        loginPass.value = '';
        if (d.ret === 'success') {
          store.loggedIn = true;
          store.user = loginUser.value;
          loginUser.value = '';
          await refreshCsrf();
          loadData();
          if (page.value === 'dashboard' && dashTab.value === 'status') startStatusRefresh();
          if (page.value === 'dashboard' && dashTab.value === 'overview') loadOverview();
        } else {
          loginError.value = d.message || '登录失败';
        }
      } catch (e) {
        loginError.value = e.message;
      }
      loading.value = false;
    }

    // ---- Logout ----
    async function doLogout() {
        expose('doLogout', doLogout);
      // Clear all auto-refresh timers
      clearInterval(statusTimer);
      clearInterval(healthTimer);
      clearInterval(overviewTimer);
      // Revoke session server-side (best-effort)
      try { await api('POST', '/verynginx/logout'); } catch (_) {}
      document.cookie = 'verynginx_session=; Path=/; Max-Age=0';
      csrfToken = null;
      store.loggedIn = false;
      store.user = null;
    }

    // ---- Load ----
    async function loadData() {
        expose('loadData', loadData);
      await Promise.all([loadStatus(), loadConfig()]);
      loadHealth();
    }

    async function loadStatus() {
        expose('loadStatus', loadStatus);
      try {
        const s = await api('GET', '/verynginx/status');
        status.value = s;
        // Push to connection history ring buffer (max 60 points, 3s each = 3 min)
        const h = connHistory.value;
        h.push(s.connections_active || 0);
        if (h.length > 60) h.shift();
        connHistory.value = [...h];
      } catch (e) {
        console.warn('Status refresh failed:', e.message);
      }
    }

    async function loadConfig() {
        expose('loadConfig', loadConfig);
      try {
        const d = await api('GET', '/verynginx/config');
        cfg.value = d;
        rawJson.value = JSON.stringify(d, null, 2);
      } catch (e) {
        showToast('Failed to load config: ' + e.message, 'error');
      }
    }

    async function refreshConfig(silent) {
        expose('refreshConfig', refreshConfig);
      await Promise.allSettled([loadConfig(), loadHealth()]);
      if (cfgTab.value === 'plugins') await loadPlugins();
      if (!silent) showToast('配置已刷新', 'success');
    }

    async function loadHealth() {
      try {
        const d = await api('GET', '/verynginx/upstreams/health');
        if (d.ret === 'success') healthData.value = d.data || {};
      } catch (e) {
        console.warn('Upstream health check failed:', e.message);
      }
    }

    // ---- Matchers ----
    const matcherKeys = computed(() => Object.keys(cfg.value.matcher || {}).sort());
        expose('matcherKeys', matcherKeys);
    const respKeys = computed(() => Object.keys(cfg.value.response || {}).sort());
        expose('respKeys', respKeys);

    function editMatcher(name) {
        expose('editMatcher', editMatcher);
      if (name) {
        editMatcherModal._origName = name;
        editMatcherModal.name = name;
        editMatcherModal.conditions = JSON.stringify(cfg.value.matcher[name], null, 2);
      } else {
        editMatcherModal._origName = null;
        editMatcherModal.name = '';
        editMatcherModal.conditions = '{}';
      }
      editMatcherModal.show = true;
    }

    async function saveMatcher() {
        expose('saveMatcher', saveMatcher);
      try {
        const updated = JSON.parse(editMatcherModal.conditions);
        const newCfg = JSON.parse(JSON.stringify(cfg.value));
        if (editMatcherModal._origName && editMatcherModal._origName !== editMatcherModal.name) {
          delete newCfg.matcher[editMatcherModal._origName];
        }
        newCfg.matcher[editMatcherModal.name] = updated;
        const ok = await commitConfig(newCfg);
        if (ok) editMatcherModal.show = false;
      } catch (e) {
        showToast('Invalid JSON: ' + e.message, 'error');
      }
    }

    async function deleteMatcher(name) {
        expose('deleteMatcher', deleteMatcher);
      if (!await showConfirm({ title: '删除匹配器', message: `删除匹配器 "${name}"?`, type: 'danger' })) return;
      const newCfg = JSON.parse(JSON.stringify(cfg.value));
      delete newCfg.matcher[name];
      await commitConfig(newCfg);
    }

    // ---- Config Rules CRUD ----
    function ruleEditReset() {
        expose('ruleEditReset', ruleEditReset);
      ruleEditModal.enable = true;
      ruleEditModal.matcherType = 'inline';
      ruleEditModal.matcherJson = '{}';
      ruleEditModal.action = 'block';
      ruleEditModal.code = 403;
      ruleEditModal.to_uri = '';
      ruleEditModal.upstream = '';
      ruleEditModal.root = '';
      ruleEditModal.path = '';
      ruleEditModal.expires = '';
      ruleEditModal.response = '';
    }

    function ruleOpenCreate(group) {
        expose('ruleOpenCreate', ruleOpenCreate);
      ruleEditReset();
      ruleEditModal.mode = 'create';
      ruleEditModal._group = group;
      ruleEditModal.show = true;
    }

    function ruleOpenEdit(rule, group, idx) {
        expose('ruleOpenEdit', ruleOpenEdit);
      ruleEditReset();
      ruleEditModal.mode = 'edit';
      ruleEditModal._group = group;
      ruleEditModal._index = idx;
      ruleEditModal.enable = rule.enable !== false;
      if (typeof rule.matcher === 'string') {
        ruleEditModal.matcherType = rule.matcher;
        ruleEditModal.matcherJson = '{}';
      } else {
        ruleEditModal.matcherType = 'inline';
        ruleEditModal.matcherJson = JSON.stringify(rule.matcher, null, 2);
      }
      ruleEditModal.action = rule.action || 'block';
      ruleEditModal.code = rule.code || 403;
      ruleEditModal.to_uri = rule.to_uri || '';
      ruleEditModal.upstream = rule.upstream || '';
      ruleEditModal.root = rule.root || '';
      ruleEditModal.path = rule.path || '';
      ruleEditModal.expires = rule.expires || '';
      ruleEditModal.response = typeof rule.response === 'string' ? rule.response : '';
      ruleEditModal.show = true;
    }

    function ruleEditModalChanged() {
        expose('ruleEditModalChanged', ruleEditModalChanged);
      // Clear stale fields when action changes
      if (ruleEditModal.action !== 'block') { ruleEditModal.response = ''; }
      if (ruleEditModal.action !== 'redirect' && ruleEditModal.action !== 'block') { ruleEditModal.code = 403; }
      if (ruleEditModal.action !== 'redirect' && ruleEditModal.action !== 'rewrite') { ruleEditModal.to_uri = ''; }
      if (ruleEditModal.action !== 'proxy') { ruleEditModal.upstream = ''; }
      if (ruleEditModal.action !== 'static') { ruleEditModal.root = ''; ruleEditModal.path = ''; ruleEditModal.expires = ''; }
      if (ruleEditModal.action !== 'response') { ruleEditModal.response = ''; }
    }

    function ruleBuildRule() {
        expose('ruleBuildRule', ruleBuildRule);
      const rule = { enable: ruleEditModal.enable };
      if (ruleEditModal.matcherType === 'inline') {
        try { rule.matcher = JSON.parse(ruleEditModal.matcherJson); } catch { rule.matcher = {}; }
      } else {
        rule.matcher = ruleEditModal.matcherType;
      }
      rule.action = ruleEditModal.action;
      if (ruleEditModal.action === 'block' || ruleEditModal.action === 'response') {
        if (ruleEditModal.code) rule.code = ruleEditModal.code;
        if (ruleEditModal.response) {
          try { rule.response = JSON.parse(ruleEditModal.response); } catch { rule.response = ruleEditModal.response; }
        }
      }
      if (ruleEditModal.action === 'redirect' || ruleEditModal.action === 'rewrite') {
        if (ruleEditModal.to_uri) rule.to_uri = ruleEditModal.to_uri;
      }
      if (ruleEditModal.action === 'redirect') {
        if (ruleEditModal.code) rule.code = ruleEditModal.code;
      }
      if (ruleEditModal.action === 'proxy') {
        if (ruleEditModal.upstream) rule.upstream = ruleEditModal.upstream;
      }
      if (ruleEditModal.action === 'static') {
        if (ruleEditModal.root) rule.root = ruleEditModal.root;
        if (ruleEditModal.path) rule.path = ruleEditModal.path;
        if (ruleEditModal.expires) rule.expires = ruleEditModal.expires;
      }
      return rule;
    }

    async function ruleSave() {
        expose('ruleSave', ruleSave);
      ruleSaving.value = true;
      try {
        const newCfg = JSON.parse(JSON.stringify(cfg.value));
        const group = ruleEditModal._group;
        if (!newCfg.rule) newCfg.rule = {};
        if (!newCfg.rule[group]) newCfg.rule[group] = [];
        const rule = ruleBuildRule();
        if (ruleEditModal.mode === 'create') {
          newCfg.rule[group].push(rule);
        } else {
          newCfg.rule[group][ruleEditModal._index] = rule;
        }
        const ok = await commitConfig(newCfg);
        if (ok) ruleEditModal.show = false;
      } catch (e) {
        showToast('Error: ' + e.message, 'error');
      } finally {
        ruleSaving.value = false;
      }
    }

    async function ruleDelete(rule, group, index) {
        expose('ruleDelete', ruleDelete);
      if (!await showConfirm({ title: '删除规则', message: 'Delete this rule?', type: 'danger' })) return;
      const newCfg = JSON.parse(JSON.stringify(cfg.value));
      if (!newCfg.rule || !newCfg.rule[group]) return;
      newCfg.rule[group].splice(index, 1);
      await commitConfig(newCfg);
    }

    async function ruleToggle(rule, group, index) {
        expose('ruleToggle', ruleToggle);
      const newCfg = JSON.parse(JSON.stringify(cfg.value));
      if (!newCfg.rule || !newCfg.rule[group]) return;
      const r = newCfg.rule[group][index];
      if (r) {
        r.enable = r.enable === false ? true : false;
        await commitConfig(newCfg);
      }
    }

    // ---- Save ----
    async function commitConfig(newCfg) {
        expose('commitConfig', commitConfig);
      try {
        const d = await api('POST', '/verynginx/config', newCfg);
        if (d.ret === 'success') {
          await loadConfig();
          await refreshCsrf();
          return true;
        } else {
          showToast('保存失败: ' + (d.message || d.err || '未知错误'), 'error');
          return false;
        }
      } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
        return false;
      }
    }

    async function saveRawConfig() {
        expose('saveRawConfig', saveRawConfig);
      if (!await showConfirm({
        title: '覆盖全部配置',
        message: '确定用当前 JSON 覆盖全部配置？建议先导出备份。',
        type: 'danger',
        requireInput: true,
        inputLabel: '请输入 "OVERRIDE" 确认',
        inputExpected: 'OVERRIDE',
      })) return;
      jsonError.value = '';
      jsonSaving.value = true;
      try {
        const parsed = JSON.parse(rawJson.value);
        const d = await api('POST', '/verynginx/config', parsed);
        if (d.ret === 'success') {
          await loadConfig();
          await refreshCsrf();
        } else {
          jsonError.value = d.message || d.err || '保存失败';
        }
      } catch (e) {
        jsonError.value = e.message;
      }
      jsonSaving.value = false;
    }

    // Auto-refresh status every 3s
    let statusTimer;
    function startStatusRefresh() {
        expose('startStatusRefresh', startStatusRefresh);
      clearInterval(statusTimer);
      loadStatus();
      statusTimer = setInterval(loadStatus, 3000);
    }
    watch([page, dashTab], ([p, d]) => {
      if (p === 'dashboard' && d === 'status') startStatusRefresh();
      else clearInterval(statusTimer);
    });
    // Stop all auto-refresh polling when the session ends (logout or expiry).
    // api() sets store.loggedIn=false on 401/403, so timer callbacks stop
    // firing session_expired requests instead of polling every 3-10s.
    watch(() => store.loggedIn, (loggedIn) => {
      if (!loggedIn) {
        clearInterval(statusTimer);
        clearInterval(healthTimer);
        clearInterval(overviewTimer);
      }
    });
    // Kick off auto-refresh on first mount based on landing view
    Vue.nextTick(() => {
      if (store.loggedIn) {
        if (page.value === 'dashboard' && dashTab.value === 'status') startStatusRefresh();
        if (page.value === 'dashboard' && dashTab.value === 'overview') {
          loadOverview();
          overviewTimer = setInterval(loadOverview, 5000);
        }
      }
    });

    // Auto-refresh health every 10s when on Upstreams tab
    let healthTimer;
    function startHealthRefresh() {
        expose('startHealthRefresh', startHealthRefresh);
      clearInterval(healthTimer);
      loadHealth();
      healthTimer = setInterval(loadHealth, 10000);
    }
    watch(cfgTab, (tab) => {
      if (tab === 'upstreams') startHealthRefresh();
      else clearInterval(healthTimer);
      if (tab === 'system') loadDictUsage();
    });

    watch(page, (p) => {
      if (p === 'config') refreshConfig(true);
      if (p === 'kb') kbFormDirty.value = false;
    });

    watch(kbTimelineFilter, () => {
      if (page.value === 'kb' && kbTab.value === 'timeline') loadKbTimeline();
    });

    // ---- Dict Usage ----
    async function loadDictUsage() {
        expose('loadDictUsage', loadDictUsage);
      try {
        const text = await api('GET', '/verynginx/metrics', null, { text: true });
        const parsed = parsePrometheus(typeof text === 'string' ? text : '');
        const dicts = [];
        const pctMap = {}, usedMap = {}, capMap = {};
        for (const [key, vals] of Object.entries(parsed)) {
          for (const [labels, val] of Object.entries(vals)) {
            const lb = JSON.parse(labels);
            if (key.startsWith('shared_dict_usage_pct')) {
              pctMap[lb.dict] = val;
            } else if (key.startsWith('shared_dict_usage_bytes')) {
              usedMap[lb.dict] = val;
            } else if (key.startsWith('shared_dict_capacity_bytes')) {
              capMap[lb.dict] = val;
            }
          }
        }
        for (const name of Object.keys(pctMap).sort()) {
          dicts.push({
            name,
            pct: pctMap[name] || 0,
            used: usedMap[name] || 0,
            cap: capMap[name] || 0
          });
        }
        dictUsage.value = dicts;
      } catch (e) {
        console.warn('Dict usage load failed:', e.message);
      }
    }

    // ---- Version ----
    async function loadVersion() {
      try {
        const d = await api('GET', '/verynginx/version');
        if (d.ret === 'success') versionInfo.value = d.data;
      } catch (e) {
        console.warn('Version load failed:', e.message);
      }
    }

    // ---- Overview ----
    function parsePrometheus(text) {
        expose('parsePrometheus', parsePrometheus);
      const result = {};
      const lines = text.split('\n');
      for (const line of lines) {
        if (line.startsWith('#') || !line.trim()) continue;
        // Match: name{labels} value
        const m = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{.*?\})?\s+([0-9.e+\-]+)/);
        if (!m) continue;
        const name = m[1];
        const labelStr = m[2] || '';
        const value = parseFloat(m[3]);
        // Parse labels
        const labels = {};
        if (labelStr) {
          const inner = labelStr.slice(1, -1);
          for (const pair of inner.split(',')) {
            const eq = pair.indexOf('=');
            if (eq < 0) continue;
            const lk = pair.slice(0, eq).trim();
            const lv = pair.slice(eq + 1).replace(/^"|"$/g, '');
            labels[lk] = lv;
          }
        }
        if (!result[name]) result[name] = {};
        const lk = JSON.stringify(labels);
        result[name][lk] = value;
      }
      return result;
    }

    async function loadOverview() {
        expose('loadOverview', loadOverview);
      const o = { conn_active: 0, req_rate: 0, up_healthy: 0, up_total: 0, waf_hits: 0, dicts: [], top_uris: [], plugin_errors: [] };
      try {
        // Status: connection counts
        const s = await api('GET', '/verynginx/status');
        o.conn_active = s.connections_active || 0;

        // Health: upstream node status
        const h = await api('GET', '/verynginx/upstreams/health');
        if (h.ret === 'success') {
          for (const [name, nodes] of Object.entries(h.data || {})) {
            for (const n of nodes) {
              o.up_total++;
              if (n.healthy && !n.circuit_open) o.up_healthy++;
            }
          }
        }

        // Metrics: shared dict usage, plugin errors, request total
        const m = await api('GET', '/verynginx/metrics', null, { text: true });
        const parsed = parsePrometheus(typeof m === 'string' ? m : '');

        for (const [key, vals] of Object.entries(parsed)) {
          if (key.startsWith('shared_dict_usage_pct')) {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              if (lb.dict) o.dicts.push({ name: lb.dict, pct: val, used: 0, cap: 0 });
            }
          } else if (key.startsWith('shared_dict_usage_bytes')) {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              const d = (o.dicts || []).find(x => x.name === lb.dict);
              if (d) { d.used = val; if (!d.cap) { const p = parsed['shared_dict_capacity_bytes']; if (p) for (const [lk, v] of Object.entries(p)) { const l = JSON.parse(lk); if (l.dict === lb.dict) d.cap = v; } } }
            }
          } else if (key === 'vn_plugin_errors_total') {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              o.plugin_errors.push({ plugin: lb.plugin || '?', phase: lb.phase || '?', count: val });
            }
          } else if (key === 'plugin_duration_seconds_count') {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              o._plugin_dur_count = o._plugin_dur_count || {};
              const k = (lb.plugin || '?') + '|' + (lb.phase || '?');
              o._plugin_dur_count[k] = val;
            }
          } else if (key === 'plugin_duration_seconds_sum') {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              o._plugin_dur_sum = o._plugin_dur_sum || {};
              const k = (lb.plugin || '?') + '|' + (lb.phase || '?');
              o._plugin_dur_sum[k] = val;
            }
          } else if (key === 'vn_requests_total') {
            o.req_rate = Math.round(Object.values(vals)[0] || 0);
          }
        }

        // Summary: top URIs
        const sum = await api('GET', '/verynginx/summary?type=short');
        if (sum.ret === 'success' && sum.data) {
          const entries = Object.entries(sum.data).map(([uri, v]) => ({
            uri,
            count: v.count || 0,
            bytes: v.bytes || 0,
            success_rate: v.count ? ((v.success || 0) / v.count * 100) : 100
          }));
          entries.sort((a, b) => b.count - a.count);
          o.top_uris = entries.slice(0, 10);
        }

        // WAF hits summary
        try {
          const w = await api('GET', '/verynginx/waf/stats');
          if (w.ret === 'success' && w.data) {
            o.waf_hits = Object.values(w.data).reduce((s, r) => s + (r.hits || 0), 0);
          }
        } catch (e) {
          console.warn('Overview WAF stats failed:', e.message);
        }

        // Reputation summary
        try {
          const r = await api('GET', '/verynginx/reputation/stats');
          if (r.ret === 'success' && r.data) {
            o.flagged = r.data.flagged || 0;
          }
        } catch (e) {
          console.warn('Overview reputation stats failed:', e.message);
        }
      } catch (e) {
        console.warn('Overview load error:', e.message);
      }
      // Merge plugin errors with duration into plugin_perf
      const perfMap = {};
      for (const e of (o.plugin_errors || [])) {
        const k = e.plugin + '|' + e.phase;
        perfMap[k] = { plugin: e.plugin, phase: e.phase, errors: e.count, avg_ms: 0, count: 0 };
      }
      for (const [k, cnt] of Object.entries(o._plugin_dur_count || {})) {
        if (!perfMap[k]) perfMap[k] = { plugin: k.split('|')[0], phase: k.split('|')[1], errors: 0, avg_ms: 0, count: 0 };
        perfMap[k].count = cnt;
      }
      for (const [k, sum] of Object.entries(o._plugin_dur_sum || {})) {
        if (perfMap[k]) {
          perfMap[k].avg_ms = perfMap[k].count > 0 ? (sum / perfMap[k].count) * 1000 : 0;
        }
      }
      o.plugin_perf = Object.values(perfMap).sort((a, b) => b.avg_ms - a.avg_ms);
      delete o.plugin_errors;
      delete o._plugin_dur_count;
      delete o._plugin_dur_sum;
      o.dicts = (o.dicts || []).sort((a, b) => b.pct - a.pct).slice(0, 6);
      overview.value = o;
    }

    // Auto-refresh overview every 5s
    let overviewTimer;
    watch([page, dashTab], ([p, d]) => {
      if (p === 'dashboard' && d === 'overview') {
        clearInterval(overviewTimer);
        loadOverview();
        overviewTimer = setInterval(loadOverview, 5000);
      } else {
        clearInterval(overviewTimer);
      }
    });

    watch([page, advTab], ([p, d]) => {
      if (p === 'advanced') {
        if (d === 'fingerprints') loadFingerprints();
        else loadAudit();
      }
    });

    // ---- Stats ----
    async function loadStats() {
        expose('loadStats', loadStats);
      statsError.value = '';
      try {
        statsData.value = await api('GET', `/verynginx/summary?type=${statsType.value}`);
      } catch (e) {
        statsError.value = e.message;
      }
      loadTopPaths();
    }

    // ---- Helpers ----
    function formatTime(t) {
        expose('formatTime', formatTime);
      if (!t) return '-';
      return new Date(t * 1000).toLocaleString();
    }

    function formatBytes(b) {
        expose('formatBytes', formatBytes);
      if (b == null) return '-';
      if (b < 1024) return b.toFixed(0) + ' B';
      if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
      return (b / 1048576).toFixed(1) + ' MB';
    }

    function calcSuccess(v) {
        expose('calcSuccess', calcSuccess);
      let ok = 0, total = 0;
      for (const code in v.status || {}) {
        const c = v.status[code];
        total += c;
        if (parseInt(code) < 400) ok += c;
      }
      return total ? ((ok / total) * 100).toFixed(1) : '0.0';
    }

    function successClass(v) {
        expose('successClass', successClass);
      const p = parseFloat(calcSuccess(v));
      if (p >= 99) return 'tag-ok';
      if (p >= 90) return 'tag-warn';
      return 'tag-err';
    }

    function summarizeRule(r) {
        expose('summarizeRule', summarizeRule);
      const parts = [];
      if (r.to_uri) parts.push('→ ' + r.to_uri);
      if (r.upstream) parts.push('→ ' + r.upstream);
      if (r.code) parts.push('HTTP ' + r.code);
      if (r.scheme) parts.push(r.scheme);
      if (r.rate) parts.push(r.rate);
      return parts.join(', ') || '-';
    }

    function actionClass(a) {
        expose('actionClass', actionClass);
      if (a === 'block' || a === 'filter') return 'tag-err';
      if (a === 'accept' || a === 'proxy' || a === 'static') return 'tag-ok';
      return 'tag-warn';
    }

    // ---- WAF Methods ----
    function sevClass(s) {
        expose('sevClass', sevClass);
      if (s === 'critical') return 'tag-err';
      if (s === 'high') return 'tag-warn';
      return 'tag-ok';
    }

    function fmtTime(ts) {
        expose('fmtTime', fmtTime);
      if (!ts) return '-';
      const d = new Date(ts * 1000);
      return d.toLocaleString();
    }

    async function loadWafRules() {
        expose('loadWafRules', loadWafRules);
      wafError.value = '';
      try {
        const params = new URLSearchParams();
        params.append('page', wafPagination.page);
        params.append('limit', wafPagination.limit);
        if (wafFilterCat.value) params.append('category', wafFilterCat.value);
        if (wafFilterSev.value) params.append('severity', wafFilterSev.value);
        const d = await api('GET', '/verynginx/waf/rules?' + params.toString());
        if (d.ret === 'success') {
          wafRules.value = d.data.rules;
          wafCategories.value = d.data.categories || {};
          wafPagination.page = d.data.pagination.page;
          wafPagination.limit = d.data.pagination.limit;
          wafPagination.total = d.data.pagination.total;
          wafPagination.total_pages = d.data.pagination.total_pages;
        } else {
          wafError.value = d.message || 'Failed to load rules';
        }
      } catch (e) {
        wafError.value = e.message;
      }
    }

    function formatNumber(n) {
        expose('formatNumber', formatNumber);
      if (n == null) return '0';
      return Number(n).toLocaleString();
    }

    function formatAgo(seconds) {
        expose('formatAgo', formatAgo);
      if (seconds < 60) return seconds + 's ago';
      if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
      if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
      return Math.floor(seconds / 86400) + 'd ago';
    }

    async function loadWafStats() {
        expose('loadWafStats', loadWafStats);
      wafStatsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/stats');
        if (d.ret === 'success') {
          wafStatsData.value = d.data;
        } else {
          wafStatsError.value = d.message || 'Failed to load stats';
        }
      } catch (e) {
        wafStatsError.value = e.message;
      }
    }

    async function loadWafHistory() {
        expose('loadWafHistory', loadWafHistory);
      wafHistError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/rules/history');
        if (d.ret === 'success') {
          wafHistory.value = d.data;
        } else {
          wafHistError.value = d.message || 'Failed to load history';
        }
      } catch (e) {
        wafHistError.value = e.message;
      }
    }

    function remaining(expiresAt) {
        expose('remaining', remaining);
      if (!expiresAt) return '-';
      const sec = Math.max(0, Math.floor((expiresAt * 1000 - Date.now()) / 1000));
      if (sec === 0) return 'expired';
      return `${sec}s`;
    }

    async function loadRepData() {
        expose('loadRepData', loadRepData);
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
        expose('repClear', repClear);
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
        expose('repAddWhitelist', repAddWhitelist);
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
        expose('repRemoveWhitelist', repRemoveWhitelist);
      if (!await showConfirm({ title: '移除白名单', message: `从白名单移除 ${ip}?`, type: 'danger' })) return;
      try {
        await api('DELETE', '/verynginx/reputation/whitelist?ip=' + encodeURIComponent(ip));
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repPersist() {
        expose('repPersist', repPersist);
      if (!await showConfirm({ title: '持久化声誉数据', message: '立即将 IP 声誉数据持久化到磁盘？', type: 'primary' })) return;
      try {
        await api('POST', '/verynginx/reputation/persist');
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repLookup() {
        expose('repLookup', repLookup);
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

    function auditActionClass(a) {
        expose('auditActionClass', auditActionClass);
      if (!a) return '';
      if (a.startsWith('login')) return a === 'login_success' ? 'tag-ok' : 'tag-err';
      if (a.startsWith('waf_rule')) return 'tag-warn';
      if (a === 'POST' || a === 'PUT' || a === 'DELETE') return 'tag-warn';
      return '';
    }

    async function loadAudit() {
        expose('loadAudit', loadAudit);
      auditError.value = '';
      try {
        let url = '/verynginx/audit?limit=500';
        if (auditFilterUser.value) url += '&user=' + encodeURIComponent(auditFilterUser.value);
        if (auditFilterAction.value) url += '&action=' + encodeURIComponent(auditFilterAction.value);
        if (auditFilterSince.value) {
          const sinceTs = Math.floor(new Date(auditFilterSince.value).getTime() / 1000);
          url += '&since=' + sinceTs;
        }
        if (auditFilterUntil.value) {
          const untilTs = Math.floor(new Date(auditFilterUntil.value).getTime() / 1000);
          url += '&until=' + untilTs;
        }
        const d = await api('GET', url);
        if (d.ret === 'success') {
          auditEntries.value = d.data || [];
        } else {
          auditError.value = d.message || 'Failed to load audit';
        }
      } catch (e) {
        auditError.value = e.message;
      }
    }

    let auditClearGuard = false;
    function clearAuditFilters() {
        expose('clearAuditFilters', clearAuditFilters);
      auditClearGuard = true;
      if (auditFilterTimer) { clearTimeout(auditFilterTimer); auditFilterTimer = null; }
      auditFilterUser.value = '';
      auditFilterAction.value = '';
      auditFilterSince.value = '';
      auditFilterUntil.value = '';
      loadAudit();
    }

    function setAuditSincePreset(preset) {
        expose('setAuditSincePreset', setAuditSincePreset);
      const now = new Date();
      let since = new Date(now);
      if (preset === '1h') since.setHours(now.getHours() - 1);
      else if (preset === '24h') since.setHours(now.getHours() - 24);
      else if (preset === '7d') since.setDate(now.getDate() - 7);
      else if (preset === 'today') since.setHours(0, 0, 0, 0);
      const pad = n => String(n).padStart(2, '0');
      const val = `${since.getFullYear()}-${pad(since.getMonth()+1)}-${pad(since.getDate())}T${pad(since.getHours())}:${pad(since.getMinutes())}`;
      auditClearGuard = true;
      auditFilterSince.value = val;
      loadAudit();
    }

    let auditFilterTimer = null;
    watch([auditFilterUser, auditFilterAction, auditFilterSince, auditFilterUntil], () => {
      if (auditClearGuard) { auditClearGuard = false; return; }
      if (auditFilterTimer) clearTimeout(auditFilterTimer);
      auditFilterTimer = setTimeout(() => loadAudit(), 400);
    });

    async function loadWafData() {
        expose('loadWafData', loadWafData);
      await loadWafRules();
      if (wafTab.value === 'attacks') await loadWafAttackData();
      if (wafTab.value === 'rules' && wafRuleView.value === 'analytics') await loadWafAnalytics();
      if (wafTab.value === 'rules' && wafRuleView.value === 'recs') await loadRecs();
      if (wafTab.value === 'history') { await loadWafHistory(); await loadPendingRules(); }
    }

    async function loadWafAttackData() {
        expose('loadWafAttackData', loadWafAttackData);
      if (wafAttackView.value === 'stats') await loadWafStats();
      if (wafAttackView.value === 'timeline') await loadWafTimeline();
      if (wafAttackView.value === 'hits') await loadWafHits();
    }

    function wafOpenCreate() {
        expose('wafOpenCreate', wafOpenCreate);
      wafEditModal.mode = 'create';
      wafEditModal.id = '';
      wafEditModal.name = '';
      wafEditModal.description = '';
      wafEditModal.category = '';
      wafEditModal.severity = '';
      wafEditModal.action = 'block';
      wafEditModal.code = 403;
      wafEditModal.matcherJson = '{}';
      wafEditModal.tagsStr = '';
      wafEditModal.rateLimitEnabled = false;
      wafEditModal.rateLimitMax = 10;
      wafEditModal.rateLimitWindow = 60;
      wafEditModal.rateLimitAction = 'log';
      wafEditError.value = '';
      wafEditModal.show = true;
    }

    function wafOpenEdit(rule) {
        expose('wafOpenEdit', wafOpenEdit);
      wafEditModal.mode = 'edit';
      wafEditModal.id = rule.id;
      wafEditModal.name = rule.name;
      wafEditModal.description = rule.description || '';
      wafEditModal.category = rule.category;
      wafEditModal.severity = rule.severity;
      wafEditModal.action = rule.action;
      wafEditModal.code = rule.code || 403;
      wafEditModal.matcherJson = JSON.stringify(rule.matcher, null, 2);
      wafEditModal.tagsStr = (rule.tags || []).join(', ');
      if (rule.rate_limit && rule.rate_limit.enable) {
        wafEditModal.rateLimitEnabled = true;
        wafEditModal.rateLimitMax = rule.rate_limit.max_hits || 10;
        wafEditModal.rateLimitWindow = rule.rate_limit.window || 60;
        wafEditModal.rateLimitAction = rule.rate_limit.action || 'log';
      } else {
        wafEditModal.rateLimitEnabled = false;
      }
      wafEditModal._originalRule = JSON.stringify({
        name: rule.name, description: rule.description || '',
        category: rule.category, severity: rule.severity,
        action: rule.action, code: rule.code || 403,
        matcher: rule.matcher, tags: rule.tags || [],
        rate_limit: rule.rate_limit || {}
      }, null, 2);
      wafEditError.value = '';
      wafEditModal.show = true;
    }

    function wafDiffLines() {
        expose('wafDiffLines', wafDiffLines);
      if (wafEditModal.mode === 'create') return [];
      try {
        const orig = JSON.parse(wafEditModal._originalRule);
        const changed = {
          name: wafEditModal.name,
          description: wafEditModal.description || '',
          category: wafEditModal.category,
          severity: wafEditModal.severity,
          action: wafEditModal.action,
          code: wafEditModal.code || 403,
          matcher: JSON.parse(wafEditModal.matcherJson),
          tags: wafEditModal.tagsStr.split(',').map(t => t.trim()).filter(t => t),
          rate_limit: wafEditModal.rateLimitEnabled ? {
            enable: true, max_hits: wafEditModal.rateLimitMax,
            window: wafEditModal.rateLimitWindow, action: wafEditModal.rateLimitAction
          } : {}
        };
        const a = JSON.stringify(orig, null, 2).split('\n');
        const b = JSON.stringify(changed, null, 2).split('\n');
        const diff = [];
        const maxLen = Math.max(a.length, b.length);
        for (let i = 0; i < maxLen; i++) {
          const left = a[i] || '';
          const right = b[i] || '';
          if (left !== right) {
            if (left) diff.push({ type: 'removed', text: left });
            if (right) diff.push({ type: 'added', text: right });
          }
        }
        return diff;
      } catch (e) {
        return [];
      }
    }

    const VALID_CATEGORIES = ['sqli', 'xss', 'rce', 'lfi', 'path_traversal', 'scanner', 'bot', 'brute', 'spam', 'custom'];
    const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
    const VALID_ACTIONS = ['block', 'accept', 'log', 'challenge'];

    async function wafSaveRule() {
        expose('wafSaveRule', wafSaveRule);
      wafEditError.value = '';
      const m = wafEditModal;
      if (!m.name) { wafEditError.value = 'Name is required'; return; }
      if (!m.category) { wafEditError.value = 'Category is required'; return; }
      if (VALID_CATEGORIES.indexOf(m.category) === -1) { wafEditError.value = 'Invalid category: ' + m.category; return; }
      if (!m.severity) { wafEditError.value = 'Severity is required'; return; }
      if (VALID_SEVERITIES.indexOf(m.severity) === -1) { wafEditError.value = 'Invalid severity: ' + m.severity; return; }
      if (!m.action) { wafEditError.value = 'Action is required'; return; }
      if (VALID_ACTIONS.indexOf(m.action) === -1) { wafEditError.value = 'Invalid action: ' + m.action; return; }

      let matcherObj;
      try {
        matcherObj = JSON.parse(m.matcherJson);
      } catch (e) {
        wafEditError.value = 'Invalid matcher JSON: ' + e.message;
        return;
      }

      const tags = m.tagsStr.split(',').map(t => t.trim()).filter(t => t);

      const rule = {
        name: m.name,
        description: m.description || undefined,
        category: m.category,
        severity: m.severity,
        action: m.action,
        code: m.code || undefined,
        matcher: matcherObj,
        tags: tags.length ? tags : undefined
      };

      if (m.rateLimitEnabled) {
        rule.rate_limit = {
          enable: true,
          max_hits: m.rateLimitMax,
          window: m.rateLimitWindow,
          action: m.rateLimitAction
        };
      }

      wafSaving.value = true;
      try {
        let d;
        if (wafEditModal.mode === 'create') {
          d = await api('POST', '/verynginx/waf/rules', rule);
        } else {
          // Stage the change (requires confirmation via History tab)
          d = await api('POST', '/verynginx/waf/rules/' + m.id + '/stage', rule);
        }
        if (d.ret === 'success') {
          wafEditModal.show = false;
          if (wafEditModal.mode === 'edit') {
            showToast('规则变更已暂存，请在 History 标签中确认发布', 'info');
          }
          await loadWafRules();
          loadWafHistory();
        } else {
          wafEditError.value = d.message || '保存失败';
        }
      } catch (e) {
        wafEditError.value = e.message;
      }
      wafSaving.value = false;
    }

    // ---- Pending Rule Changes ----
    async function loadPendingRules() {
        expose('loadPendingRules', loadPendingRules);
      try {
        const d = await api('GET', '/verynginx/waf/rules/pending');
        if (d.ret === 'success') {
          wafPendingChanges.value = d.data || [];
        }
      } catch (e) {
        wafPendingChanges.value = [];
      }
    }

    async function confirmPendingChange(ruleId) {
        expose('confirmPendingChange', confirmPendingChange);
      if (!await showConfirm({ title: '发布暂存变更', message: `发布规则 ${ruleId} 的暂存变更？将立即生效，影响所有请求。`, type: 'danger' })) return;
      try {
        const d = await api('POST', '/verynginx/waf/rules/' + ruleId + '/confirm');
        if (d.ret === 'success') {
          showToast('规则变更已发布', 'success');
          await Promise.all([loadWafRules(), loadWafHistory(), loadPendingRules()]);
        } else {
          showToast(d.message || '发布失败', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    async function discardPendingChange(ruleId) {
        expose('discardPendingChange', discardPendingChange);
      if (!await showConfirm({ title: '丢弃暂存变更', message: `丢弃规则 ${ruleId} 的暂存变更？此操作不可恢复。`, type: 'danger' })) return;
      try {
        const d = await api('DELETE', '/verynginx/waf/rules/' + ruleId + '/pending');
        if (d.ret === 'success') {
          showToast('规则变更已丢弃', 'info');
          await loadPendingRules();
        } else {
          showToast(d.message || '丢弃失败', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    // ---- WAF Timeline ----
    async function loadWafTimeline() {
        expose('loadWafTimeline', loadWafTimeline);
      wafTimelineLoading.value = true;
      wafTimelineError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/timeline?hours=' + wafTimelineHours.value + '&bucket=' + wafTimelineBucket.value);
        if (d.ret === 'success') {
          wafTimeline.value = d.data || { buckets: [], categories: [] };
        } else {
          wafTimelineError.value = d.message || 'Failed to load timeline';
          wafTimeline.value = { buckets: [], categories: [] };
        }
      } catch (e) {
        if (e.message !== 'session_expired') wafTimelineError.value = e.message;
        wafTimeline.value = { buckets: [], categories: [] };
      } finally {
        wafTimelineLoading.value = false;
      }
    }

    const hasTimelineData = computed(() => {
      const buckets = (wafTimeline.value && wafTimeline.value.buckets) || [];
      for (const b of buckets) {
        for (const c in (b.counts || {})) {
          if (b.counts[c] > 0) return true;
        }
      }
      return false;
    });
        expose('hasTimelineData', hasTimelineData);

    function timelineBarHeight(counts, cat) {
        expose('timelineBarHeight', timelineBarHeight);
      let max = 1;
      for (const b of wafTimeline.value.buckets) {
        for (const c in b.counts) {
          if (b.counts[c] > max) max = b.counts[c];
        }
      }
      return Math.round((counts[cat] || 0) / max * 100) + '%';
    }

    function categoryColor(cat) {
        expose('categoryColor', categoryColor);
      const colors = { sqli: '#ef4444', xss: '#f97316', scanner: '#3b82f6', rce: '#dc2626',
                       path_traversal: '#f59e0b', injection: '#e11d48', other: '#6b7280' };
      return colors[cat] || '#6b7280';
    }

    // ---- Test History ----
    async function loadTestHistory() {
        expose('loadTestHistory', loadTestHistory);
      try {
        const d = await api('GET', '/verynginx/waf/test-history');
        if (d.ret === 'success') {
          wafTestHistory.value = d.data || [];
        }
      } catch (e) {
        wafTestHistory.value = [];
      }
    }

    async function clearTestHistory() {
        expose('clearTestHistory', clearTestHistory);
      if (!await showConfirm({ title: '清除测试历史', message: '确定清除全部 WAF 测试历史?', type: 'warning' })) return;
      try {
        await api('DELETE', '/verynginx/waf/test-history');
        wafTestHistory.value = [];
        showToast('测试历史已清除', 'info');
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    // ---- Hit Detail Drill-down ----
    async function openHitDetail(hit) {
        expose('openHitDetail', openHitDetail);
      wafHitDetailModal.show = true
      wafHitDetailModal.loading = true
      wafHitDetailModal.data = null
      wafHitDetailModal.error = ''
      try {
        const ringIdx = hit.ring_idx != null ? hit.ring_idx : 0
        const d = await api('GET', '/verynginx/waf/hits/' + ringIdx)
        if (d.ret === 'success') {
          wafHitDetailModal.data = d.data
        } else {
          wafHitDetailModal.error = d.message || '加载失败'
        }
      } catch (e) {
        if (e.message === 'session_expired') throw e;
        wafHitDetailModal.error = '加载命中详情失败: ' + e.message
      }
      wafHitDetailModal.loading = false
    }

    async function addToWhitelist(ip) {
        expose('addToWhitelist', addToWhitelist);
      if (!await showConfirm({ title: '加入白名单', message: `将 ${ip} 加入白名单？此后该 IP 将不受 WAF 规则限制。`, type: 'primary' })) return;
      try {
        await api('POST', '/verynginx/reputation/whitelist', { ip })
        showToast('已加入白名单: ' + ip, 'success')
        if (wafHitDetailModal.data) wafHitDetailModal.data.ip_whitelisted = true
      } catch (e) {
        showToast(e.message || 'Failed to add whitelist', 'error')
      }
    }

    async function viewIpHits(ip) {
        expose('viewIpHits', viewIpHits);
      try {
        const d = await api('GET', '/verynginx/waf/hits/by-ip?ip=' + encodeURIComponent(ip))
        if (d.ret === 'success') {
          wafIpHits.value = d.data || []
          wafIpHitsIp.value = ip
        }
      } catch (e) {
        wafIpHits.value = []
      }
    }

    async function editRuleById(ruleId) {
        expose('editRuleById', editRuleById);
      try {
        const rule = wafRules.value.find(r => r.id === ruleId);
        if (rule) {
          wafTab.value = 'rules';
          wafOpenEdit(rule);
          showToast('已定位到规则编辑器: ' + rule.name, 'info');
        } else {
          await loadWafRules();
          const r = wafRules.value.find(x => x.id === ruleId);
          if (r) {
            wafTab.value = 'rules';
            wafOpenEdit(r);
            showToast('已定位到规则编辑器: ' + r.name, 'info');
          } else {
            showToast('未找到规则: ' + ruleId, 'error');
          }
        }
      } catch (e) {
        if (e.message !== 'session_expired') showToast(e.message, 'error');
      } finally {
        wafHitDetailModal.show = false;
      }
    }

    // ---- Frequency Limit ----
    async function loadFrequencyData() {
        expose('loadFrequencyData', loadFrequencyData);
      try {
        const results = await Promise.allSettled([
          api('GET', '/verynginx/frequency/stats'),
          api('GET', '/verynginx/frequency/rules'),
          api('GET', '/verynginx/frequency/templates'),
        ]);
        const [statsRes, rulesRes, tmplRes] = results.map(r => (r.status === 'fulfilled' ? r.value : null));
        if (statsRes && statsRes.ret === 'success') freqStats.value = statsRes.data || [];
        if (rulesRes && rulesRes.ret === 'success') freqRules.value = rulesRes.data || [];
        if (tmplRes && tmplRes.ret === 'success') freqTemplates.value = tmplRes.data || [];
        freqTemplatesLoaded.value = true;
        const failures = results.filter(r => r.status === 'rejected').map(r => r.reason.message);
        if (failures.length) {
          console.warn('loadFrequencyData partial failure:', failures.join('; '));
          if (!failures.includes('session_expired')) freqError.value = '部分数据加载失败: ' + failures.join('; ');
        } else {
          freqError.value = '';
        }
      } catch (e) {
        console.warn('loadFrequencyData failed:', e.message);
        freqTemplatesLoaded.value = true;
        if (e.message !== 'session_expired') freqError.value = '加载频率限制数据失败: ' + e.message;
      }
    }

    async function previewFreqTemplate(name) {
        expose('previewFreqTemplate', previewFreqTemplate);
      try {
        const d = await api('GET', '/verynginx/frequency/templates/' + name);
        if (d.ret === 'success') {
          const r = d.data.rule || {};
          Object.assign(freqTemplateModal, {
            show: true,
            name: name,
            label: d.data.label || '',
            description: d.data.description || '',
            id: r.id || '',
            key: r.key || 'ip',
            limit: r.limit || 60,
            window: r.window || 60,
            code: r.code || 429,
            matcherJson: r.matcherJson || '{}',
          });
        } else {
          showToast(d.message || '模板未找到', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
    }

    function freqMatcherSummary(mj) {
      if (!mj || mj === '{}' || mj === '') return '';
      try {
        const obj = JSON.parse(mj);
        if (typeof obj !== 'object' || obj === null) return '';
        const keys = Object.keys(obj);
        const conds = [];
        for (const k of keys) {
          const v = obj[k];
          if (v && typeof v === 'object' && v.value != null) {
            let desc = k;
            if (v.operator === '≈') desc += ':≈' + String(v.value).slice(0, 24);
            else if (v.operator === '=') desc += ':' + String(v.value).slice(0, 24);
            else desc += ':...';
            conds.push(desc);
          } else {
            conds.push(k);
          }
        }
        return ' matcher条件=' + conds.join(', ');
      } catch (e) {
        return ' matcher=自定义';
      }
    }

    async function applyFreqTemplate() {
        expose('applyFreqTemplate', applyFreqTemplate);
      const rule = freqTemplateModal;
      if (!await showConfirm({
        title: '应用频率模板',
        message: `从模板 ${rule.label} 创建并下发限流规则？\n\n键=${rule.key} 限制=${rule.limit}/窗口=${rule.window}s 动作码=${rule.code}${freqMatcherSummary(rule.matcherJson)}`,
        type: 'primary',
      })) return;
      try {
        const overrides = {
          id: freqTemplateModal.id,
          key: freqTemplateModal.key,
          limit: freqTemplateModal.limit,
          window: freqTemplateModal.window,
          code: freqTemplateModal.code,
          matcherJson: freqTemplateModal.matcherJson,
        };
        const d = await api('POST', '/verynginx/frequency/templates/' + freqTemplateModal.name, overrides);
        if (d.ret === 'success') {
          showToast('规则已从模板创建: ' + d.data.id, 'success');
          freqTemplateModal.show = false;
          await loadFrequencyData();
        } else {
          showToast(d.message || '应用失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
    }

    // ---- GeoIP ----
    async function loadGeoIPStatus() {
        expose('loadGeoIPStatus', loadGeoIPStatus);
      try {
        const d = await api('GET', '/verynginx/geoip/status');
        if (d.ret === 'success') geoipStatus.value = d.data;
      } catch (e) {
        // silent - status is non-critical
      }
    }

    async function loadGeoIP() {
        expose('loadGeoIP', loadGeoIP);
      geoipLoading.value = true;
      geoipError.value = '';
      try {
        const [cfgRes, statsRes] = await Promise.all([
          api('GET', '/verynginx/geoip/config'),
          api('GET', '/verynginx/geoip/stats'),
        ]);
        if (cfgRes.ret === 'success') {
          const cfg = cfgRes.data || {};
          // Determine mirror source from config
          let mirror = 'auto';
          let custom_mirror_url = '';
          if (cfg.cdn_url || cfg.update_url) {
            const url = cfg.cdn_url || cfg.update_url;
            const MIRROR_MAP = {
              'https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb': 'p3terx',
              'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb': 'loyalsoldier_raw',
              'https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb': 'loyalsoldier_release',
            };
            mirror = MIRROR_MAP[url] || 'custom';
            if (mirror === 'custom') custom_mirror_url = url;
          }
          geoipConfig.value = {
            enable: cfg.enable || false,
            geodb_path: cfg.geodb_path || '',
            whitelistStr: (cfg.whitelist || []).join(','),
            blocklistStr: (cfg.blocklist || []).join(','),
            auto_update: cfg.auto_update !== false,
            update_interval_hours: cfg.update_interval_hours || 168,
            mirror, custom_mirror_url,
            license_key: cfg.license_key || '',
          };
        } else {
          geoipError.value = cfgRes.message || 'Failed to load geoip config';
        }
        if (statsRes.ret === 'success') {
          geoipStats.value = Object.entries(statsRes.data || {}).map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count).slice(0, 20);
        }
      } catch (e) {
        if (e.message !== 'session_expired') geoipError.value = e.message;
      } finally {
        geoipLoading.value = false;
      }
    }

    async function lookupGeoIP() {
        expose('lookupGeoIP', lookupGeoIP);
      if (!geoipLookupIP.value) return;
      const ip = geoipLookupIP.value.trim();
      if (!isValidIpLiteral(ip)) { showToast('IP 格式无效: ' + ip, 'error'); return; }
      try {
        const d = await api('GET', '/verynginx/geoip/lookup?ip=' + encodeURIComponent(ip));
        geoipLookupResult.value = d;
      } catch (e) {
        showToast(e.message || 'Lookup failed', 'error');
      }
    }

    async function saveGeoIPConfig() {
        expose('saveGeoIPConfig', saveGeoIPConfig);
      try {
        const MIRROR_URLS = {
          p3terx: 'https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb',
          loyalsoldier_raw: 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb',
          loyalsoldier_release: 'https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb',
        };
        let cdn_url = '';
        let update_url = '';
        if (geoipConfig.value.mirror === 'custom') {
          update_url = geoipConfig.value.custom_mirror_url || '';
        } else if (geoipConfig.value.mirror !== 'auto') {
          cdn_url = MIRROR_URLS[geoipConfig.value.mirror] || '';
        }
        const cfg = {
          enable: !!geoipConfig.value.enable,
          geodb_path: geoipConfig.value.geodb_path || '',
          whitelist: geoipConfig.value.whitelistStr.split(',').map(s => s.trim()).filter(s => s),
          blocklist: geoipConfig.value.blocklistStr.split(',').map(s => s.trim()).filter(s => s),
          auto_update: !!geoipConfig.value.auto_update,
          update_interval_hours: geoipConfig.value.update_interval_hours || 168,
          cdn_url, update_url,
          license_key: geoipConfig.value.license_key || '',
        };
        const d = await api('PUT', '/verynginx/geoip/config', cfg);
        if (d.ret === 'success') showToast('GeoIP 配置已保存', 'success');
        else showToast(d.message || '保存失败', 'error');
      } catch (e) {
        showToast(e.message || '保存失败', 'error');
      }
    }

    async function triggerGeoIPUpdate() {
        expose('triggerGeoIPUpdate', triggerGeoIPUpdate);
      if (!await showConfirm({
        title: '更新 GeoIP 数据库',
        message: '立即从数据源下载并替换 GeoIP 数据库？现有 .mmdb 将被覆盖。',
        type: 'danger',
        requireInput: true,
        inputLabel: '请输入 "UPDATE" 确认',
        inputExpected: 'UPDATE',
      })) return;
      try {
        const d = await api('POST', '/verynginx/geoip/update');
        if (d.ret === 'success') {
          showToast(d.message || 'Update successful', 'success');
          await loadGeoIP();
          // Fetch fresh status (includes DB info)
          const s = await api('GET', '/verynginx/geoip/status');
          if (s.ret === 'success') geoipStatus.value = s.data;
        } else {
          showToast(d.message || 'Update failed', 'error');
        }
      } catch (e) {
        showToast(e.message || 'Update failed', 'error');
      }
    }

    // ---- Fingerprints ----
    async function loadFingerprints() {
        expose('loadFingerprints', loadFingerprints);
      try {
        const d = await api('GET', '/verynginx/fingerprints');
        if (d.ret === 'success') {
          fingerprints.value = d.data || [];
          const cats = {};
          for (const fp of fingerprints.value) {
            if (fp.enabled) cats[fp.category] = (cats[fp.category] || 0) + 1;
          }
          fpCategories.value = cats;
        }
      } catch (e) {
        console.warn('loadFingerprints failed:', e.message);
        if (e.message !== 'session_expired') fpError.value = '加载指纹失败: ' + e.message;
      }
    }

    function openFpAdd() {
        expose('openFpAdd', openFpAdd);
      fpEditModal.hash = '';
      fpEditModal.name = '';
      fpEditModal.category = 'scanner';
      fpEditModal.action = 'block';
      fpEditModal.show = true;
    }

    async function toggleFp(fp) {
        expose('toggleFp', toggleFp);
      fpToggleBusy.value = true;
      fp.enabled = !fp.enabled;
      try {
        await saveFp(fp);
      } finally {
        fpToggleBusy.value = false;
      }
    }

    async function saveFp(fp) {
      try {
        const d = await api('PUT', '/verynginx/fingerprints', fp);
        if (d.ret === 'success') {
          await loadFingerprints();
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) {
        showToast(e.message || '保存失败', 'error');
      }
    }

    async function deleteFp(fp) {
        expose('deleteFp', deleteFp);
      if (!await showConfirm({ title: '删除指纹', message: `删除指纹 "${fp.hash}"?`, type: 'danger' })) return;
      try {
        const d = await api('DELETE', '/verynginx/fingerprints/' + fp.hash);
        if (d.ret === 'success') {
          showToast('指纹已删除', 'success');
          await loadFingerprints();
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    // ---- Kernel Blocking ----
    async function loadKbData() {
        expose('loadKbData', loadKbData);
      kbError.value = '';
      const statusRequest = (async () => {
        try {
          const d = await api('GET', '/verynginx/kernel-blocking/status');
          if (d.ret === 'success') {
            kbStatus.value = Object.assign({}, kbStatus.value, d.data || {});
            kbSyncFormFromStatus();
          } else {
            kbError.value = d.message || 'Failed to load status';
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
        expose('loadKbEntries', loadKbEntries);
      try {
        let url = '/verynginx/kernel-blocking/entries?page_size=50';
        if (cursor) url += '&cursor=' + cursor;
        if (kbFilterPolicy.value) url += '&policy=' + encodeURIComponent(kbFilterPolicy.value);
        if (kbFilterIP.value) url += '&ip=' + encodeURIComponent(kbFilterIP.value);
        const d = await api('GET', url);
        if (d.ret === 'success') {
          kbEntriesCurrentCursor.value = cursor || null;
          if (!cursor) kbEntriesPrev.value = [];
          kbEntries.value = d.data.entries || [];
          kbEntriesNext.value = d.data.next_cursor;
        } else {
          kbError.value = d.message || 'Failed to load entries';
        }
      } catch (e) { kbError.value = e.message; }
    }

    function kbEntriesPageNext() {
        expose('kbEntriesPageNext', kbEntriesPageNext);
      if (!kbEntriesNext.value) return;
      kbEntriesPrev.value.push(kbEntriesCurrentCursor.value);
      loadKbEntries(kbEntriesNext.value);
    }

    function kbEntriesPagePrev() {
        expose('kbEntriesPagePrev', kbEntriesPagePrev);
      const prev = kbEntriesPrev.value.pop();
      if (prev != null) loadKbEntries(prev);
    }

    async function loadKbCandidates(cursor) {
        expose('loadKbCandidates', loadKbCandidates);
      try {
        let url = '/verynginx/kernel-blocking/candidates?page_size=50';
        if (cursor) url += '&cursor=' + cursor;
        if (kbFilterState.value) url += '&state=' + encodeURIComponent(kbFilterState.value);
        if (kbFilterIP.value) url += '&ip=' + encodeURIComponent(kbFilterIP.value);
        const d = await api('GET', url);
        if (d.ret === 'success') {
          kbCandidatesCurrentCursor.value = cursor || null;
          if (!cursor) kbCandidatesPrev.value = [];
          kbCandidates.value = d.data.entries || [];
          kbCandidatesNext.value = d.data.next_cursor;
        } else {
          kbError.value = d.message || 'Failed to load candidates';
        }
      } catch (e) { kbError.value = e.message; }
    }

    function kbCandidatesPageNext() {
        expose('kbCandidatesPageNext', kbCandidatesPageNext);
      if (!kbCandidatesNext.value) return;
      kbCandidatesPrev.value.push(kbCandidatesCurrentCursor.value);
      loadKbCandidates(kbCandidatesNext.value);
    }

    function kbCandidatesPagePrev() {
        expose('kbCandidatesPagePrev', kbCandidatesPagePrev);
      const prev = kbCandidatesPrev.value.pop();
      if (prev != null) loadKbCandidates(prev);
    }

    async function loadKbTimeline() {
        expose('loadKbTimeline', loadKbTimeline);
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
        if (d.ret === 'success') {
          const all = d.data || [];
          kbTimeline.value = all;
        } else {
          kbError.value = d.message || 'Failed to load timeline';
        }
      } catch (e) { kbError.value = e.message; }
    }

    function kbTimelineActionLabel(action) {
        expose('kbTimelineActionLabel', kbTimelineActionLabel);
      const map = {
        'kernel_blocking.promote': '封禁',
        'kernel_blocking.clear': '解除',
        'kernel_blocking.reconcile': '协调',
        'kernel_blocking.lifecycle': '生命周期',
      };
      return map[action] || action || '-';
    }

    function kbTimelineActionClass(action) {
        expose('kbTimelineActionClass', kbTimelineActionClass);
      if (action === 'kernel_blocking.promote') return 'tag-err';
      if (action === 'kernel_blocking.clear') return 'tag-ok';
      if (action === 'kernel_blocking.reconcile') return 'tag-info';
      return 'tag-warn';
    }

    async function loadKbBucketHistory() {
        expose('loadKbBucketHistory', loadKbBucketHistory);
      kbBucketHistoryLoading.value = true;
      kbBucketHistoryError.value = '';
      try {
        const d = await api('GET', '/verynginx/kernel-blocking/bucket-history');
        if (d.ret === 'success') {
          kbBucketHistory.value = d.data.samples || [];
        } else {
          kbBucketHistoryError.value = d.message || 'Failed to load bucket history';
          kbBucketHistory.value = [];
        }
      } catch (e) {
        if (e.message !== 'session_expired') kbBucketHistoryError.value = e.message;
        kbBucketHistory.value = [];
      } finally {
        kbBucketHistoryLoading.value = false;
      }
    }

    async function loadKbDiff() {
      try {
        const d = await api('GET', '/verynginx/kernel-blocking/diff');
        if (d.ret === 'success') kbDiff.value = d.data || kbDiff.value;
      } catch (e) { /* non-critical */ }
    }

    async function loadKbDashboard() {
        expose('loadKbDashboard', loadKbDashboard);
      await Promise.all([loadKbBucketHistory(), loadKbDiff()]);
    }

    async function enableCcEnforceReady() {
        expose('enableCcEnforceReady', enableCcEnforceReady);
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
          cfg.value = full;
          await loadKbData();
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbSaveSettings() {
        expose('kbSaveSettings', kbSaveSettings);
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
          cfg.value = full;
          kbFormDirty.value = false;
          await loadKbData();
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbPromote() {
        expose('kbPromote', kbPromote);
      if (!kbNewIP.value) { showToast('请输入 IP', 'error'); return; }
      // Client-side IP format validation (IPv4/IPv6 literal)
      const ip = kbNewIP.value.trim();
      if (!isValidIpLiteral(ip, false)) { showToast('IP 格式无效: ' + ip, 'error'); return; }
      if (!await showConfirm({ title: '手动封禁 IP', message: `手动封禁 ${ip} 策略 ${kbNewPolicy.value} TTL ${kbNewTTL.value}秒?`, type: 'danger' })) return;
      kbBusy.value = true;
      try {
        const d = await api('POST', '/verynginx/kernel-blocking/promote', {
          ip: kbNewIP.value, policy: kbNewPolicy.value, ttl: kbNewTTL.value
        });
        if (d.ret === 'success') {
          showToast('IP ' + kbNewIP.value + ' blocked', 'success');
          kbNewIP.value = '';
          await loadKbData();
        } else {
          showToast(d.message || 'Promote failed', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }

    async function kbPromoteIp(ip, policy) {
        expose('kbPromoteIp', kbPromoteIp);
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
        expose('kbReconcile', kbReconcile);
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
        expose('kbClear', kbClear);
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
        expose('kbPause', kbPause);
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
        expose('kbFlushAuto', kbFlushAuto);
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
          showToast('Auto entries flushed (' + ((d.data && d.data.removed) || 0) + ')', 'success');
          await loadKbData();
        } else {
          showToast(d.message || 'Flush failed', 'error');
        }
      } catch (e) { showToast(e.message, 'error'); }
      finally { kbBusy.value = false; }
    }


    function openFreqRuleCreate() {
        expose('openFreqRuleCreate', openFreqRuleCreate);
      freqRuleModal.mode = 'create';
      freqRuleModal._matcherRef = null;
      freqRuleModal.id = 'freq_' + Date.now();
      freqRuleModal.key = 'ip';
      freqRuleModal.limit = 60;
      freqRuleModal.window = 60;
      freqRuleModal.code = 429;
      freqRuleModal.enable = true;
      freqRuleModal.matcherJson = '{}';
      freqRuleModal.show = true;
    }

    function openFreqRuleEdit(rule) {
        expose('openFreqRuleEdit', openFreqRuleEdit);
      freqRuleModal.mode = 'edit';
      freqRuleModal.id = rule.id;
      freqRuleModal.key = rule.key || 'ip';
      freqRuleModal.limit = rule.limit;
      freqRuleModal.window = rule.window;
      freqRuleModal.code = rule.code || 429;
      freqRuleModal.enable = rule.enable !== false;
      if (typeof rule.matcher === 'string') {
        freqRuleModal._matcherRef = rule.matcher;
        freqRuleModal.matcherJson = '{}';
      } else {
        freqRuleModal._matcherRef = null;
        freqRuleModal.matcherJson = (rule.matcher && typeof rule.matcher === 'object')
          ? JSON.stringify(rule.matcher, null, 2) : '{}';
      }
      freqRuleModal.show = true;
    }

    async function saveFreqRule() {
        expose('saveFreqRule', saveFreqRule);
      try {
        // Client-side validation
        if (!freqRuleModal.key || freqRuleModal.key.trim() === '') {
          showToast('限速键 (key) 不能为空', 'error'); return;
        }
        const limit = Number(freqRuleModal.limit);
        const window = Number(freqRuleModal.window);
        const code = Number(freqRuleModal.code);
        if (!limit || limit < 1) { showToast('limit 必须 >= 1', 'error'); return; }
        if (!window || window < 1) { showToast('window 必须 >= 1 秒', 'error'); return; }
        if (!code || code < 100 || code > 599) { showToast('响应码必须是 100-599 之间的合法状态码', 'error'); return; }

        let matcher = {};
        try {
          if (freqRuleModal._matcherRef) {
            matcher = null;
          } else if (freqRuleModal.matcherJson && freqRuleModal.matcherJson !== '{}') {
            matcher = JSON.parse(freqRuleModal.matcherJson);
          }
        } catch (e) {
          showToast('匹配器 JSON 格式无效: ' + e.message, 'error');
          return;
        }
        const rule = {
          id: freqRuleModal.id,
          key: freqRuleModal.key,
          limit,
          window,
          code,
          enable: freqRuleModal.enable,
        };
        if (freqRuleModal._matcherRef) {
          rule.matcher = freqRuleModal._matcherRef;
        } else if (Object.keys(matcher).length > 0) {
          rule.matcher = matcher;
        }
        const d = await api('POST', '/verynginx/frequency/rules', rule);
        if (d.ret === 'success') {
          freqRuleModal.show = false;
          showToast('规则已保存', 'success');
          await loadFrequencyData();
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    async function deleteFreqRule(rule) {
        expose('deleteFreqRule', deleteFreqRule);
      if (!await showConfirm({ title: '删除频率规则', message: `删除频率规则 "${rule.id}"?`, type: 'danger' })) return;
      try {
        const d = await api('DELETE', '/verynginx/frequency/rules/' + rule.id);
        if (d.ret === 'success') {
          showToast('规则已删除', 'success');
          await loadFrequencyData();
        } else {
          showToast(d.message || '删除失败', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    async function wafDeleteRule(rule) {
        expose('wafDeleteRule', wafDeleteRule);
      if (!await showConfirm({ title: '删除 WAF 规则', message: `删除规则 "${rule.name}"? 此操作不可撤销。`, type: 'danger' })) return;
      wafDeleteBusy.value = true;
      try {
        const d = await api('DELETE', '/verynginx/waf/rules/' + rule.id);
        if (d.ret === 'success') {
          await loadWafRules();
        } else {
          wafError.value = d.message || 'Delete failed';
        }
      } catch (e) {
        wafError.value = e.message;
      } finally {
        wafDeleteBusy.value = false;
      }
    }

    async function wafToggleRule(rule) {
        expose('wafToggleRule', wafToggleRule);
      const enable = rule.enable === false;
      if (!await showConfirm({ title: enable ? '启用规则' : '停用规则', message: enable ? `启用规则 ${rule.name}？将立即生效。` : `停用规则 ${rule.name}？将立即停止拦截。`, type: enable ? 'primary' : 'warning' })) return;
      wafToggleBusy.value = true;
      try {
        const endpoint = enable ? 'enable' : 'disable';
        const d = await api('POST', '/verynginx/waf/rules/' + rule.id + '/' + endpoint);
        if (d.ret === 'success') {
          rule.enable = enable;
        }
      } catch (e) {
        wafError.value = e.message;
      } finally {
        wafToggleBusy.value = false;
      }
    }

    function wafPage(p) {
        expose('wafPage', wafPage);
      wafPagination.page = p;
      loadWafRules();
    }

    function wafFilterChange() {
        expose('wafFilterChange', wafFilterChange);
      wafPagination.page = 1;
      loadWafRules();
    }

    async function wafRefreshAll() {
        expose('wafRefreshAll', wafRefreshAll);
      await loadWafData();
    }

    // ---- WAF Recommender ----
    const recs = ref([]);
        expose('recs', recs);
    const recStats = ref(null);
        expose('recStats', recStats);
    const recError = ref('');
        expose('recError', recError);
    const recLoading = ref(false);
        expose('recLoading', recLoading);

    async function loadRecs() {
        expose('loadRecs', loadRecs);
      recError.value = '';
      try {
        const [d, s] = await Promise.all([
          api('GET', '/verynginx/waf/recommendations'),
          api('GET', '/verynginx/waf/recommendations/stats')
        ]);
        if (d.ret === 'success') recs.value = d.data || [];
        if (s.ret === 'success') recStats.value = s.data;
      } catch (e) {
        recError.value = e.message;
      }
    }

    async function runRecAnalysis() {
        expose('runRecAnalysis', runRecAnalysis);
      recLoading.value = true;
      recError.value = '';
      try {
        const d = await api('POST', '/verynginx/waf/recommendations/analyze');
        if (d.ret === 'success') {
          showToast('Analysis complete: ' + (d.data.new_recommendations || 0) + ' new recommendations', 'success');
          await loadRecs();
        }
      } catch (e) {
        recError.value = e.message;
      } finally {
        recLoading.value = false;
      }
    }

    async function applyRec(id) {
        expose('applyRec', applyRec);
      try {
        const d = await api('POST', '/verynginx/waf/recommendations/' + id + '/apply');
        if (d.ret === 'success') {
          showToast('Rule applied successfully', 'success');
          await loadRecs();
        }
      } catch (e) {
        recError.value = e.message;
      }
    }

    async function dismissRec(id) {
        expose('dismissRec', dismissRec);
      try {
        await api('POST', '/verynginx/waf/recommendations/' + id + '/dismiss');
        await loadRecs();
      } catch (e) {
        recError.value = e.message;
      }
    }

    async function wafRollback(version) {
        expose('wafRollback', wafRollback);
      if (!await showConfirm({
        title: '回滚规则版本',
        message: `回滚到版本 ${version}? 这将替换所有当前规则。`,
        type: 'danger',
        requireInput: true,
        inputLabel: `请输入版本号 ${version} 确认`,
        inputExpected: version,
      })) return;
      wafRolling.value = true;
      try {
        const d = await api('POST', '/verynginx/waf/rules/rollback', { version: version });
        if (d.ret === 'success') {
          await loadWafRules();
        } else {
          wafHistError.value = d.message || '回滚失败';
        }
      } catch (e) {
        wafHistError.value = e.message;
      }
      wafRolling.value = false;
    }

    // ---- WAF Hits ----
    async function loadWafHits() {
        expose('loadWafHits', loadWafHits);
      wafHitsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/hits?limit=' + wafHitsLimit.value);
        if (d.ret === 'success') {
          wafHits.value = d.data || [];
          wafHitsTime.value = wafHits.value.length ? new Date().toLocaleTimeString() : '';
        } else {
          wafHitsError.value = d.message || 'Failed to load hits';
        }
      } catch (e) {
        wafHitsError.value = e.message;
      }
    }

    function wafLoadMoreHits() {
        expose('wafLoadMoreHits', wafLoadMoreHits);
      wafHitsLimit.value = 100;
      loadWafHits();
    }

    // ---- WAF Analytics ----
    async function loadWafAnalytics() {
        expose('loadWafAnalytics', loadWafAnalytics);
      wafAnalyticsLoading.value = true;
      wafAnalyticsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/analytics');
        if (d.ret === 'success') {
          wafAnalytics.value = d.data || { rules: [], dead_rules: [] };
        } else {
          wafAnalyticsError.value = d.message || 'Failed to load analytics';
          wafAnalytics.value = { rules: [], dead_rules: [] };
        }
      } catch (e) {
        if (e.message !== 'session_expired') wafAnalyticsError.value = e.message;
        wafAnalytics.value = { rules: [], dead_rules: [] };
      } finally {
        wafAnalyticsLoading.value = false;
      }
    }

    function gradeStyle(g) {
        expose('gradeStyle', gradeStyle);
      const colors = { 'A+': '#16a34a', A: '#22c55e', B: '#f59e0b', C: '#f97316', D: '#ef4444' };
      return { background: colors[g] || '#6b7280', color: '#fff' };
    }

    // ---- Plugins ----
    async function loadPlugins() {
        expose('loadPlugins', loadPlugins);
      pluginsError.value = '';
      try {
        const d = await api('GET', '/verynginx/plugins');
        if (d.ret === 'success') {
          plugins.value = d.data || [];
        } else {
          pluginsError.value = d.message || 'Failed to load plugins';
        }
      } catch (e) {
        pluginsError.value = e.message;
      }
    }

    async function togglePlugin(p) {
        expose('togglePlugin', togglePlugin);
      pluginsError.value = '';
      const old = p.enable;
      p.enable = !p.enable;
      try {
        const d = await api('POST', '/verynginx/plugins/' + p.name + '/toggle');
        if (d.ret === 'success') {
          p.enable = d.data.enable;
          if (p.enable !== !old) loadPlugins();
          showToast(p.enable ? '已启用 ' + p.name : '已停用 ' + p.name, p.enable ? 'success' : 'info');
        } else {
          p.enable = old;
          pluginsError.value = d.message || 'Toggle failed';
        }
      } catch (e) {
        p.enable = old;
        pluginsError.value = e.message;
      }
    }

    // ---- Config Export/Import ----
    const importFileInput = ref(null);
        expose('importFileInput', importFileInput);

    async function exportConfig() {
        expose('exportConfig', exportConfig);
      try {
        const opts = { method: 'GET', credentials: 'same-origin' };
        if (csrfToken) {
          opts.headers = { 'X-CSRF-Token': csrfToken };
        }
        const res = await fetch('/verynginx/config/export', opts);
        // Session expired or unauthorized — logout and redirect to login
        if (res.status === 401 || res.status === 403) {
          csrfToken = null;
          if (typeof store !== 'undefined') {
            store.loggedIn = false;
            store.user = null;
          }
          throw new Error('session_expired');
        }
        if (!res.ok) { showToast('Export failed: HTTP ' + res.status, 'error'); return; }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = 'config.json';
        document.body.appendChild(a); a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (e) {
        if (e.message !== 'session_expired') showToast('Export failed: ' + e.message, 'error');
      }
    }

    function importConfig() {
        expose('importConfig', importConfig);
      configImportError.value = '';
      configImportOk.value = '';
      if (importFileInput.value) importFileInput.value.click();
    }

    async function onImportFile(e) {
        expose('onImportFile', onImportFile);
      configImportError.value = '';
      configImportOk.value = '';
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      if (file.size > 1048576) { configImportError.value = 'File too large (max 1 MB)'; return; }
      const text = await file.text();
      try {
        const parsed = JSON.parse(text);
        const d = await api('POST', '/verynginx/config/import', parsed);
        if (d.ret === 'success') {
          configImportOk.value = '配置导入成功。';
          await loadConfig();
        } else {
          configImportError.value = d.message || '导入失败';
        }
      } catch (e) {
        configImportError.value = e.message;
      }
      e.target.value = '';
    }

    // ---- Top Paths ----
    async function loadTopPaths() {
        expose('loadTopPaths', loadTopPaths);
      try {
        const d = await api('GET', '/verynginx/stats/top-paths?limit=20');
        if (d.ret === 'success') {
          topPaths.value = d.data || [];
        }
      } catch (e) {
        console.warn('Top paths load failed:', e.message);
      }
    }

    async function wafRunTest() {
        expose('wafRunTest', wafRunTest);
      wafTestError.value = '';
      wafTestResults.value = null;

      let rule, cases;
      try {
        rule = JSON.parse(wafTestRuleJson.value);
      } catch (e) {
        wafTestError.value = 'Invalid rule JSON: ' + e.message;
        return;
      }
      try {
        cases = JSON.parse(wafTestCasesJson.value);
        if (!Array.isArray(cases) || !cases.length) throw new Error('Must be a non-empty array');
      } catch (e) {
        wafTestError.value = 'Invalid test cases JSON: ' + e.message;
        return;
      }

      wafTesting.value = true;
      try {
        const d = await api('POST', '/verynginx/waf/rules/test', { rule, test_cases: cases });
        if (d.ret === 'success') {
          wafTestResults.value = d.data;
          await loadTestHistory();
        } else {
          wafTestError.value = d.message || 'Test failed';
        }
      } catch (e) {
        wafTestError.value = e.message;
      }
      wafTesting.value = false;
    }

    return Object.fromEntries(exports);
  }
  
});

app.mount('#app');
