// vn-waf.js - Domain module for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    
    window.VN.modules['vnwaf'] = function createvnwafModule(ctx) {
        const { expose, api, store, page, dashTab, advTab, loading, loginUser, loginPass, loginError, status, connHistory, cfg, healthData, overview, dictUsage, cfgTab, theme, rawJson, jsonError, jsonSaving, statsData, statsType, statsError, expandedUri, editMatcherModal, isValidIpLiteral, refreshCsrf, refreshCsrfOnce, csrfToken } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;
        
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
        
        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();