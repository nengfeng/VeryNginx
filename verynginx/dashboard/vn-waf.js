// vn-waf.js - WAF module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-config.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnwaf'] = function createvnwafModule(shared) {
        const { ctx, view, api, store, page, showToast, showConfirm, validateMatcherIps } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- WAF State ----
    const wafTab = ref('rules');
    const wafRuleView = ref('list');
    const wafAttackView = ref('stats');
    const wafError = ref('');
    const wafRules = ref([]);
    const wafCategories = ref({});
    const wafPagination = reactive({ page: 1, limit: 20, total: 0, total_pages: 0 });
    const wafFilterCat = ref('');
    const wafFilterSev = ref('');
    const wafStatsData = ref(null);
    const wafStatsError = ref('');
    const wafHistory = ref([]);
    const wafHistError = ref('');
    const wafRolling = ref(false);
    const wafToggleBusy = ref(false);
    const wafDeleteBusy = ref(false);
    const wafEditModal = reactive({
      show: false, mode: 'create',
      id: '', name: '', description: '', category: '', severity: '',
      action: 'block', code: 403, matcherJson: '{}',
      tagsStr: '',
      rateLimitEnabled: false, rateLimitMax: 10, rateLimitWindow: 60, rateLimitAction: 'log'
    });
    const wafEditError = ref('');
    const wafSaving = ref(false);
    const wafTestRuleJson = ref('');
    const wafTestCasesJson = ref('');
    const wafTestError = ref('');
    const wafTesting = ref(false);
    const wafTestResults = ref(null);
    const wafHits = ref([]);
    const wafHitsError = ref('');
    const wafHitsTime = ref('');
    const wafHitsLimit = ref(50);
    const wafAnalytics = ref({ rules: [], dead_rules: [] });
    const wafAnalyticsLoading = ref(false);
    const wafAnalyticsError = ref('');
    const wafPendingChanges = ref([]);
    const wafPendingError = ref('');
    const wafTimeline = ref({ buckets: [], categories: [], bucket_minutes: 5, hours: 1 });
    const wafTimelineHours = ref(1);
    const wafTimelineBucket = ref(5);
    const wafTimelineLoading = ref(false);
    const wafTimelineError = ref('');
    const wafTestHistory = ref([]);
    const wafTestHistoryError = ref('');
    const wafHitDetailModal = reactive({ show: false, loading: false, data: null, error: '' });
    const wafIpHits = ref([]);
    const wafIpHitsIp = ref('');
    const wafIpHitsError = ref('');
    const recs = ref([]);
    const recStats = ref(null);
    const recActionLoading = ref(false);
    const pendingActionLoading = ref(false);
    const recError = ref('');
    const recLoading = ref(false);

    // Stale-response guards for list/timeline/stats loaders.
    const gWafRules = shared.createStaleGuard();
    const gWafStats = shared.createStaleGuard();
    const gWafHistory = shared.createStaleGuard();
    const gWafAttack = shared.createStaleGuard();
    const gWafTimeline = shared.createStaleGuard();
    const gWafHits = shared.createStaleGuard();
    const gWafAnalytics = shared.createStaleGuard();
    const gRecs = shared.createStaleGuard();
    const gViewIpHits = shared.createStaleGuard();


    // ---- WAF Methods ----
    function sevClass(s) {
      if (s === 'critical') return 'tag-err';
      if (s === 'high') return 'tag-warn';
      return 'tag-ok';
    }

    function fmtTime(ts) {
      if (!ts) return '-';
      const d = new Date(ts * 1000);
      return d.toLocaleString();
    }

    async function loadWafRules() {
      const tok = gWafRules.mark();
      wafError.value = '';
      try {
        const params = new URLSearchParams();
        params.append('page', wafPagination.page);
        params.append('limit', wafPagination.limit);
        if (wafFilterCat.value) params.append('category', wafFilterCat.value);
        if (wafFilterSev.value) params.append('severity', wafFilterSev.value);
        const d = await api('GET', '/verynginx/waf/rules?' + params.toString());
        if (!gWafRules.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafRules.value = d.data.rules;
          wafCategories.value = d.data.categories || {};
          wafPagination.page = d.data.pagination.page;
          wafPagination.limit = d.data.pagination.limit;
          wafPagination.total = d.data.pagination.total;
          wafPagination.total_pages = d.data.pagination.total_pages;
        } else {
          wafError.value = d.message || '规则加载失败';
        }
      } catch (e) { if (gWafRules.isCurrent(tok)) wafError.value = e.message; }
    }

    function formatNumber(n) {
      if (n == null) return '0';
      return Number(n).toLocaleString();
    }

    function formatAgo(seconds) {
      if (seconds < 60) return seconds + ' 秒前';
      if (seconds < 3600) return Math.floor(seconds / 60) + ' 分钟前';
      if (seconds < 86400) return Math.floor(seconds / 3600) + ' 小时前';
      return Math.floor(seconds / 86400) + ' 天前';
    }

    async function loadWafStats() {
      const tok = gWafStats.mark();
      wafStatsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/stats');
        if (!gWafStats.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafStatsData.value = d.data;
        } else {
          wafStatsError.value = d.message || '统计加载失败';
        }
      } catch (e) { if (gWafStats.isCurrent(tok)) wafStatsError.value = e.message; }
    }

    async function loadWafHistory() {
      const tok = gWafHistory.mark();
      wafHistError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/rules/history');
        if (!gWafHistory.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafHistory.value = d.data;
        } else {
          wafHistError.value = d.message || '历史加载失败';
        }
      } catch (e) { if (gWafHistory.isCurrent(tok)) wafHistError.value = e.message; }
    }

    function remaining(expiresAt) {
      if (!expiresAt) return '-';
      const sec = Math.max(0, Math.floor((expiresAt * 1000 - Date.now()) / 1000));
      if (sec === 0) return '已过期';
      return `${sec}s`;
    }

    async function loadWafData() {
      await loadWafRules();
      if (wafTab.value === 'attacks') await loadWafAttackData();
      if (wafTab.value === 'rules' && wafRuleView.value === 'analytics') await loadWafAnalytics();
      if (wafTab.value === 'rules' && wafRuleView.value === 'recs') await loadRecs();
      if (wafTab.value === 'history') { await loadWafHistory(); await loadPendingRules(); }
    }

    async function loadWafAttackData() {
      if (wafAttackView.value === 'stats') await loadWafStats();
      if (wafAttackView.value === 'timeline') await loadWafTimeline();
      if (wafAttackView.value === 'hits') await loadWafHits();
    }

    function wafOpenCreate() {
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

    const wafDiffLines = computed(() => {
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
    });

    const VALID_CATEGORIES = ['sqli', 'xss', 'rce', 'lfi', 'path_traversal', 'scanner', 'bot', 'brute', 'spam', 'custom'];
    const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
    const VALID_ACTIONS = ['block', 'accept', 'log', 'challenge'];


    async function wafSaveRule() {
      wafEditError.value = '';
      const m = wafEditModal;
      if (!m.name) { wafEditError.value = '请输入规则名称'; return; }
      if (!m.category) { wafEditError.value = '请选择分类'; return; }
      if (VALID_CATEGORIES.indexOf(m.category) === -1) { wafEditError.value = '无效分类: ' + m.category; return; }
      if (!m.severity) { wafEditError.value = '请选择严重级别'; return; }
      if (VALID_SEVERITIES.indexOf(m.severity) === -1) { wafEditError.value = '无效严重级别: ' + m.severity; return; }
      if (!m.action) { wafEditError.value = '请选择动作'; return; }
      if (VALID_ACTIONS.indexOf(m.action) === -1) { wafEditError.value = '无效动作: ' + m.action; return; }

      let matcherObj;
      try {
        matcherObj = JSON.parse(m.matcherJson);
      } catch (e) {
        wafEditError.value = 'Invalid matcher JSON: ' + e.message;
        return;
      }

      // Validate numeric fields before sending. A bad code/limit would be
      // silently accepted by the server and yield an invalid rule.
      if (m.code !== '' && m.code != null) {
        const code = Number(m.code);
        if (!Number.isInteger(code) || code < 100 || code > 599) {
          wafEditError.value = '响应码必须是 100-599 之间的整数: ' + m.code;
          return;
        }
      }
      if (m.rateLimitEnabled) {
        const max = Number(m.rateLimitMax);
        const win = Number(m.rateLimitWindow);
        if (!Number.isInteger(max) || max < 1) {
          wafEditError.value = '速率限制最大命中必须是 >= 1 的整数';
          return;
        }
        if (!Number.isInteger(win) || win < 1) {
          wafEditError.value = '速率限制窗口必须是 >= 1 的整数（秒）';
          return;
        }
      }

      // Pre-check any inline matcher IP values so an obviously invalid address
      // is rejected client-side instead of silently matching nothing (or
      // everything) server-side.
      const ipErr = validateMatcherIps(matcherObj);
      if (ipErr) { wafEditError.value = ipErr; return; }

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
      wafPendingError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/rules/pending');
        if (d.ret === 'success') {
          wafPendingChanges.value = d.data || [];
        } else {
          wafPendingError.value = d.message || '暂存变更加载失败';
        }
      } catch (e) {
        if (e.message !== 'session_expired') wafPendingError.value = e.message;
      }
    }

    async function confirmPendingChange(ruleId) {
      if (pendingActionLoading.value) return;
      pendingActionLoading.value = true;
      try {
        if (!await showConfirm({ title: '发布暂存变更', message: `发布规则 ${ruleId} 的暂存变更？将立即生效，影响所有请求。`, type: 'danger' })) return;
        const d = await api('POST', '/verynginx/waf/rules/' + ruleId + '/confirm');
        if (d.ret === 'success') {
          showToast('规则变更已发布', 'success');
          await Promise.all([loadWafRules(), loadWafHistory(), loadPendingRules()]);
        } else {
          showToast(d.message || '发布失败', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      } finally {
        pendingActionLoading.value = false;
      }
    }

    async function discardPendingChange(ruleId) {
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
      const tok = gWafTimeline.mark();
      wafTimelineLoading.value = true;
      wafTimelineError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/timeline?hours=' + wafTimelineHours.value + '&bucket=' + wafTimelineBucket.value);
        if (!gWafTimeline.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafTimeline.value = d.data || { buckets: [], categories: [] };
        } else {
          wafTimelineError.value = d.message || '时间线加载失败';
          wafTimeline.value = { buckets: [], categories: [] };
        }
      } catch (e) {
        if (e.message !== 'session_expired' && gWafTimeline.isCurrent(tok)) wafTimelineError.value = e.message;
        if (gWafTimeline.isCurrent(tok)) wafTimeline.value = { buckets: [], categories: [] };
      } finally {
        // A late stale response must not extinguish a newer request's spinner.
        if (gWafTimeline.isCurrent(tok)) wafTimelineLoading.value = false;
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

    function timelineBarHeight(counts, cat) {
      let max = 1;
      for (const b of wafTimeline.value.buckets) {
        for (const c in b.counts) {
          if (b.counts[c] > max) max = b.counts[c];
        }
      }
      return Math.round((counts[cat] || 0) / max * 100) + '%';
    }

    function categoryColor(cat) {
      const colors = { sqli: '#ef4444', xss: '#f97316', scanner: '#3b82f6', rce: '#dc2626',
                       path_traversal: '#f59e0b', injection: '#e11d48', other: '#6b7280' };
      return colors[cat] || '#6b7280';
    }


    // ---- Test History ----
    async function loadTestHistory() {
      wafTestHistoryError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/test-history');
        if (d.ret === 'success') {
          wafTestHistory.value = d.data || [];
        } else {
          wafTestHistoryError.value = d.message || '测试历史加载失败';
        }
      } catch (e) {
        if (e.message !== 'session_expired') wafTestHistoryError.value = e.message;
      }
    }

    async function clearTestHistory() {
      if (!await showConfirm({ title: '清除测试历史', message: '确定清除全部 WAF 测试历史?', type: 'warning' })) return;
      try {
        await api('DELETE', '/verynginx/waf/test-history');
        wafTestHistory.value = [];
        showToast('测试历史已清除', 'info');
      } catch (e) {
        showToast(e.message, 'error');
      }
    }


    // ---- WAF Rule Test ----
    async function wafRunTest() {
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


    // ---- Hit Detail Drill-down ----
    async function openHitDetail(hit) {
      // Drop any per-IP hits from a previously opened detail so the modal
      // can't show one IP's hits under another IP's detail.
      wafIpHits.value = []
      wafIpHitsIp.value = ''
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
      const tok = gViewIpHits.mark();
      wafIpHitsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/hits/by-ip?ip=' + encodeURIComponent(ip))
        if (!gViewIpHits.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafIpHits.value = d.data || []
          wafIpHitsIp.value = ip
        } else {
          wafIpHitsError.value = d.message || 'IP 命中记录加载失败';
          wafIpHits.value = [];
        }
      } catch (e) {
        if (gViewIpHits.isCurrent(tok)) {
          if (e.message !== 'session_expired') wafIpHitsError.value = e.message;
          wafIpHits.value = [];
        }
      }
    }

    async function editRuleById(ruleId) {
      try {
        const rule = wafRules.value.find(r => r.id === ruleId);
        if (rule) {
          wafTab.value = 'rules';
          wafOpenEdit(rule);
          showToast('已定位到规则编辑器: ' + rule.name, 'info');
          return;
        }
        // Not on the current page — fetch the single rule directly instead of
        // reloading the current page (which would never find an out-of-range id).
        const d = await api('GET', '/verynginx/waf/rules/' + encodeURIComponent(ruleId));
        if (d.ret === 'success' && d.data) {
          wafTab.value = 'rules';
          wafOpenEdit(d.data);
          showToast('已定位到规则编辑器: ' + (d.data.name || ruleId), 'info');
        } else {
          showToast('未找到规则: ' + ruleId, 'error');
        }
      } catch (e) {
        if (e.message !== 'session_expired') showToast(e.message, 'error');
      } finally {
        wafHitDetailModal.show = false;
      }
    }


    // ---- WAF Hits ----
    async function loadWafHits() {
      const tok = gWafHits.mark();
      wafHitsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/hits?limit=' + wafHitsLimit.value);
        if (!gWafHits.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafHits.value = d.data || [];
          wafHitsTime.value = wafHits.value.length ? new Date().toLocaleTimeString() : '';
        } else {
          wafHitsError.value = d.message || '命中记录加载失败';
        }
      } catch (e) { if (gWafHits.isCurrent(tok)) wafHitsError.value = e.message; }
    }

    function wafLoadMoreHits() {
      wafHitsLimit.value = 100;
      loadWafHits();
    }


    // ---- WAF Analytics ----
    async function loadWafAnalytics() {
      const tok = gWafAnalytics.mark();
      wafAnalyticsLoading.value = true;
      wafAnalyticsError.value = '';
      try {
        const d = await api('GET', '/verynginx/waf/analytics');
        if (!gWafAnalytics.isCurrent(tok)) return;
        if (d.ret === 'success') {
          wafAnalytics.value = d.data || { rules: [], dead_rules: [] };
        } else {
          wafAnalyticsError.value = d.message || '分析数据加载失败';
          wafAnalytics.value = { rules: [], dead_rules: [] };
        }
      } catch (e) {
        if (e.message !== 'session_expired' && gWafAnalytics.isCurrent(tok)) wafAnalyticsError.value = e.message;
        if (gWafAnalytics.isCurrent(tok)) wafAnalytics.value = { rules: [], dead_rules: [] };
      } finally {
        if (gWafAnalytics.isCurrent(tok)) wafAnalyticsLoading.value = false;
      }
    }

    function gradeStyle(g) {
      const colors = { 'A+': '#16a34a', A: '#22c55e', B: '#f59e0b', C: '#f97316', D: '#ef4444' };
      return { background: colors[g] || '#6b7280', color: '#fff' };
    }


    // ---- WAF Recommender ----
    async function loadRecs() {
      const tok = gRecs.mark();
      recError.value = '';
      try {
        const [d, s] = await Promise.all([
          api('GET', '/verynginx/waf/recommendations'),
          api('GET', '/verynginx/waf/recommendations/stats')
        ]);
        if (!gRecs.isCurrent(tok)) return;
        if (d.ret === 'success') recs.value = d.data || [];
        if (s.ret === 'success') recStats.value = s.data;
      } catch (e) { if (gRecs.isCurrent(tok)) recError.value = e.message; }
    }

    async function runRecAnalysis() {
      recLoading.value = true;
      recError.value = '';
      try {
        const d = await api('POST', '/verynginx/waf/recommendations/analyze');
        if (d.ret === 'success') {
          showToast('分析完成：新增 ' + (d.data.new_recommendations || 0) + ' 条建议', 'success');
          await loadRecs();
        }
      } catch (e) {
        recError.value = e.message;
      } finally {
        recLoading.value = false;
      }
    }

    async function applyRec(id) {
      if (recActionLoading.value) return;
      recActionLoading.value = true;
      try {
        const d = await api('POST', '/verynginx/waf/recommendations/' + id + '/apply');
        if (d.ret === 'success') {
          showToast('规则已应用', 'success');
          await loadRecs();
        } else {
          recError.value = d.message || 'Apply failed';
        }
      } catch (e) {
        recError.value = e.message;
      } finally {
        recActionLoading.value = false;
      }
    }

    async function dismissRec(id) {
      if (recActionLoading.value) return;
      recActionLoading.value = true;
      try {
        await api('POST', '/verynginx/waf/recommendations/' + id + '/dismiss');
        await loadRecs();
      } catch (e) {
        recError.value = e.message;
      } finally {
        recActionLoading.value = false;
      }
    }

    async function wafRollback(version) {
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


    // ---- Rule delete / toggle / pagination (used from KB page too) ----
    async function wafDeleteRule(rule) {
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
      wafPagination.page = p;
      loadWafRules();
    }

    function wafFilterChange() {
      wafPagination.page = 1;
      loadWafRules();
    }

    async function wafRefreshAll() {
      await loadWafData();
    }


    // ---- Exports ----
    view('wafTab', wafTab);
    view('wafRuleView', wafRuleView);
    view('wafAttackView', wafAttackView);
    view('wafError', wafError);
    view('wafRules', wafRules);
    view('wafCategories', wafCategories);
    view('wafPagination', wafPagination);
    view('wafFilterCat', wafFilterCat);
    view('wafFilterSev', wafFilterSev);
    view('wafStatsData', wafStatsData);
    view('wafStatsError', wafStatsError);
    view('wafHistory', wafHistory);
    view('wafHistError', wafHistError);
    view('wafRolling', wafRolling);
    ctx('wafToggleBusy', wafToggleBusy);
    view('wafDeleteBusy', wafDeleteBusy);
    view('wafEditModal', wafEditModal);
    view('wafEditError', wafEditError);
    view('wafSaving', wafSaving);
    view('wafTestRuleJson', wafTestRuleJson);
    view('wafTestCasesJson', wafTestCasesJson);
    view('wafTestError', wafTestError);
    view('wafTesting', wafTesting);
    view('wafTestResults', wafTestResults);
    view('wafHits', wafHits);
    view('wafHitsError', wafHitsError);
    view('wafHitsTime', wafHitsTime);
    view('wafHitsLimit', wafHitsLimit);
    view('wafAnalytics', wafAnalytics);
    view('wafAnalyticsLoading', wafAnalyticsLoading);
    view('wafAnalyticsError', wafAnalyticsError);
    view('wafPendingChanges', wafPendingChanges);
    view('wafPendingError', wafPendingError);
    view('wafTimeline', wafTimeline);
    view('wafTimelineHours', wafTimelineHours);
    view('wafTimelineBucket', wafTimelineBucket);
    view('wafTimelineLoading', wafTimelineLoading);
    view('wafTimelineError', wafTimelineError);
    view('wafTestHistory', wafTestHistory);
    view('wafTestHistoryError', wafTestHistoryError);
    view('wafHitDetailModal', wafHitDetailModal);
    view('wafIpHits', wafIpHits);
    view('wafIpHitsIp', wafIpHitsIp);
    view('wafIpHitsError', wafIpHitsError);
    view('recs', recs);
    view('recStats', recStats);
    view('recActionLoading', recActionLoading);
    view('pendingActionLoading', pendingActionLoading);
    view('recError', recError);
    view('recLoading', recLoading);
    view('sevClass', sevClass);
    view('fmtTime', fmtTime);
    ctx('loadWafRules', loadWafRules);
    view('formatNumber', formatNumber);
    view('formatAgo', formatAgo);
    view('loadWafStats', loadWafStats);
    view('loadWafHistory', loadWafHistory);
    view('remaining', remaining);
    ctx('loadWafData', loadWafData);
    view('loadWafAttackData', loadWafAttackData);
    view('wafOpenCreate', wafOpenCreate);
    view('wafOpenEdit', wafOpenEdit);
    view('wafDiffLines', wafDiffLines);
    view('wafSaveRule', wafSaveRule);
    ctx('loadPendingRules', loadPendingRules);
    view('confirmPendingChange', confirmPendingChange);
    view('discardPendingChange', discardPendingChange);
    view('loadWafTimeline', loadWafTimeline);
    view('hasTimelineData', hasTimelineData);
    view('timelineBarHeight', timelineBarHeight);
    view('categoryColor', categoryColor);
    ctx('loadTestHistory', loadTestHistory);
    view('clearTestHistory', clearTestHistory);
    view('wafRunTest', wafRunTest);
    view('openHitDetail', openHitDetail);
    view('addToWhitelist', addToWhitelist);
    view('viewIpHits', viewIpHits);
    view('editRuleById', editRuleById);
    view('loadWafHits', loadWafHits);
    view('wafLoadMoreHits', wafLoadMoreHits);
    view('loadWafAnalytics', loadWafAnalytics);
    view('gradeStyle', gradeStyle);
    view('loadRecs', loadRecs);
    view('runRecAnalysis', runRecAnalysis);
    view('applyRec', applyRec);
    view('dismissRec', dismissRec);
    view('wafRollback', wafRollback);
    view('wafDeleteRule', wafDeleteRule);
    view('wafToggleRule', wafToggleRule);
    view('wafPage', wafPage);
    view('wafFilterChange', wafFilterChange);
    view('wafRefreshAll', wafRefreshAll);

    // Wipe per-session WAF data on logout.
    shared.onLogout(() => {
      wafRules.value = [];
      wafCategories.value = {};
      wafStatsData.value = null;
      wafStatsError.value = '';
      wafHistory.value = [];
      wafHistError.value = '';
      wafAnalytics.value = { rules: [], dead_rules: [] };
      wafPendingChanges.value = [];
      wafTimeline.value = { buckets: [], categories: [], bucket_minutes: 5, hours: 1 };
      wafTestHistory.value = [];
      wafHits.value = [];
      wafHitsError.value = '';
      wafHitDetailModal.show = false;
      wafHitDetailModal.data = null;
      wafHitDetailModal.error = '';
      wafHitDetailModal.loading = false;
      wafIpHits.value = [];
      wafIpHitsIp.value = '';
      recs.value = [];
      recStats.value = null;
      recError.value = '';
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();