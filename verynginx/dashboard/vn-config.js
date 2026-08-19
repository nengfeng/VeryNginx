// vn-config.js - Domain module for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    
    window.VN.modules['vnconfig'] = function createvnconfigModule(ctx) {
        const { expose, api, store, page, dashTab, advTab, loading, loginUser, loginPass, loginError, status, connHistory, cfg, healthData, overview, dictUsage, cfgTab, theme, rawJson, jsonError, jsonSaving, statsData, statsType, statsError, expandedUri, editMatcherModal, isValidIpLiteral, refreshCsrf, refreshCsrfOnce, csrfToken } = ctx;
        
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
        
        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();