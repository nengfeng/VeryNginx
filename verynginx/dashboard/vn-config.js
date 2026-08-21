// vn-config.js - Config module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-dashboard.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnconfig'] = function createvnconfigModule(shared) {
        const { ctx, view, api, store, page, cfgTab, cfg, rawJson, jsonError, jsonSaving, editMatcherModal, loadConfig, refreshCsrf, showToast, showConfirm, validateMatcherIps } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Config Rule Editor State ----
    const ruleEditModal = reactive({
      show: false, mode: 'create', _group: '', _index: -1,
      enable: true, matcherType: 'inline', matcherJson: '{}',
      action: 'block', code: 403, to_uri: '', upstream: '',
      root: '', path: '', expires: '', response: '',
    });
    const ruleSaving = ref(false);
    const upstreamKeys = computed(() => Object.keys(cfg.value.backend_upstream || {}).sort());
    view('upstreamKeys', upstreamKeys);


    // ---- Matchers ----
    const matcherKeys = computed(() => Object.keys(cfg.value.matcher || {}).sort());
    view('matcherKeys', matcherKeys);
    const respKeys = computed(() => Object.keys(cfg.value.response || {}).sort());
    view('respKeys', respKeys);

    function editMatcher(name) {
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

    const matcherSaving = ref(false);
    async function saveMatcher() {
      const name = (editMatcherModal.name || '').trim();
      if (!name) { showToast('匹配器名称不能为空', 'error'); return; }
      let updated;
      try {
        updated = JSON.parse(editMatcherModal.conditions);
      } catch (e) {
        showToast('Invalid JSON: ' + e.message, 'error');
        return;
      }
      // Reject empty / duplicate names instead of silently overwriting.
      const isRename = editMatcherModal._origName && editMatcherModal._origName !== name;
      if (!isRename && cfg.value.matcher && cfg.value.matcher[name]) {
        showToast('匹配器名称已存在: ' + name, 'error');
        return;
      }
      const ipErr = validateMatcherIps(updated);
      if (ipErr) { showToast(ipErr, 'error'); return; }

      if (matcherSaving.value) return;
      matcherSaving.value = true;
      try {
        const newCfg = JSON.parse(JSON.stringify(cfg.value));
        if (isRename) delete newCfg.matcher[editMatcherModal._origName];
        newCfg.matcher[name] = updated;
        const ok = await commitConfig(newCfg);
        if (ok) editMatcherModal.show = false;
      } catch (e) {
        showToast('Invalid JSON: ' + e.message, 'error');
      } finally {
        matcherSaving.value = false;
      }
    }

    async function deleteMatcher(name) {
      if (!await showConfirm({ title: '删除匹配器', message: `删除匹配器 "${name}"?`, type: 'danger' })) return;
      const newCfg = JSON.parse(JSON.stringify(cfg.value));
      delete newCfg.matcher[name];
      await commitConfig(newCfg);
    }


    // ---- Config Rules CRUD ----
    function ruleEditReset() {
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
      ruleEditReset();
      ruleEditModal.mode = 'create';
      ruleEditModal._group = group;
      ruleEditModal.show = true;
    }

    function ruleOpenEdit(rule, group, idx) {
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
      // Clear fields that the newly selected action does not use. `response`
      // is used by both `block` and `response`; `code` by `block`, `response`
      // and `redirect` — so neither must be wiped when switching to those.
      const a = ruleEditModal.action;
      if (a !== 'block' && a !== 'response') { ruleEditModal.response = ''; }
      if (a !== 'block' && a !== 'response' && a !== 'redirect') { ruleEditModal.code = 403; }
      if (a !== 'redirect' && a !== 'rewrite') { ruleEditModal.to_uri = ''; }
      if (a !== 'proxy') { ruleEditModal.upstream = ''; }
      if (a !== 'static') { ruleEditModal.root = ''; ruleEditModal.path = ''; ruleEditModal.expires = ''; }
    }

    function ruleBuildRule() {
      const rule = { enable: ruleEditModal.enable };
      if (ruleEditModal.matcherType === 'inline') {
        let matcher;
        try {
          matcher = JSON.parse(ruleEditModal.matcherJson);
        } catch (e) {
          throw new Error('匹配器 JSON 格式无效: ' + e.message);
        }
        if (typeof matcher !== 'object' || matcher === null || Array.isArray(matcher)) {
          throw new Error('匹配器必须是 JSON 对象 (如 {"URI": {"value": "/"}})');
        }
        // An empty matcher matches EVERY request (matcher/init.lua:48-51). A
        // typo'd JSON that we silently downgraded to {} would, with a block
        // action, take down the whole site with no warning — so reject it.
        if (Object.keys(matcher).length === 0) {
          throw new Error('匹配器不能为空: 空匹配器会匹配全部请求 (block 动作将导致全站阻断)');
        }
        rule.matcher = matcher;
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
        showToast('保存失败: ' + e.message, 'error');
      } finally {
        ruleSaving.value = false;
      }
    }

    async function ruleDelete(rule, group, index) {
      if (!await showConfirm({ title: '删除规则', message: 'Delete this rule?', type: 'danger' })) return;
      const newCfg = JSON.parse(JSON.stringify(cfg.value));
      if (!newCfg.rule || !newCfg.rule[group]) return;
      newCfg.rule[group].splice(index, 1);
      await commitConfig(newCfg);
    }

    async function ruleToggle(rule, group, index) {
      const newCfg = JSON.parse(JSON.stringify(cfg.value));
      if (!newCfg.rule || !newCfg.rule[group]) return;
      const r = newCfg.rule[group][index];
      if (r) {
        r.enable = r.enable === false ? true : false;
        await commitConfig(newCfg);
      }
    }


    // ---- Save ----
    // Serialize config writes within a tab so two quick saves can't race and
    // lose each other's changes (read-modify-write on the full config). This
    // does not cover concurrent edits across separate browser tabs — that
    // needs server-side optimistic concurrency.
    let configSaveChain = Promise.resolve();
    async function _commitConfig(newCfg) {
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
    function commitConfig(newCfg) {
      const run = configSaveChain.then(() => _commitConfig(newCfg));
      configSaveChain = run.catch(() => {});
      return run;
    }

    async function saveRawConfig() {
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


    // ---- Import / Export ----
    const importFileInput = ref(null);
    view('importFileInput', importFileInput);
    const configImportError = ref('');
    view('configImportError', configImportError);
    const configImportOk = ref('');
    view('configImportOk', configImportOk);

    function exportConfig() {
      const blob = new Blob([JSON.stringify(cfg.value, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'verynginx-config.json';
      a.click();
      URL.revokeObjectURL(url);
    }

    function importConfig() {
      if (importFileInput.value) importFileInput.value.click();
    }

    async function onImportFile(e) {
      const file = e.target && e.target.files && e.target.files[0];
      if (!file) return;
      configImportError.value = '';
      configImportOk.value = '';
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        if (!await showConfirm({
          title: '导入全量配置',
          message: '这将用文件中的配置全量覆盖当前配置并立即生效。建议先导出备份。',
          type: 'danger',
          requireInput: true,
          inputLabel: '请输入 "IMPORT" 确认',
          inputExpected: 'IMPORT',
        })) return;
        const d = await api('POST', '/verynginx/config', parsed);
        if (d.ret === 'success') {
          await loadConfig();
          await refreshCsrf();
          configImportOk.value = '配置已成功导入并生效';
        } else {
          configImportError.value = d.message || d.err || '导入失败';
        }
      } catch (err) {
        configImportError.value = '导入失败: ' + err.message;
      } finally {
        if (e.target) e.target.value = '';
      }
    }

    // Refresh config data when entering the config page
    watch(page, (p) => {
      if (p === 'config') { if (shared.refreshConfig) shared.refreshConfig(true); }
    });

    // ---- Exports ----
    view('ruleEditModal', ruleEditModal);
    view('ruleSaving', ruleSaving);
    view('editMatcher', editMatcher);
    view('saveMatcher', saveMatcher);
    view('matcherSaving', matcherSaving);
    view('deleteMatcher', deleteMatcher);
    ctx('ruleEditReset', ruleEditReset);
    view('ruleOpenCreate', ruleOpenCreate);
    view('ruleOpenEdit', ruleOpenEdit);
    view('ruleEditModalChanged', ruleEditModalChanged);
    ctx('ruleBuildRule', ruleBuildRule);
    view('ruleSave', ruleSave);
    view('ruleDelete', ruleDelete);
    view('ruleToggle', ruleToggle);
    ctx('commitConfig', commitConfig);
    view('saveRawConfig', saveRawConfig);
    view('exportConfig', exportConfig);
    view('importConfig', importConfig);
    view('onImportFile', onImportFile);

    // Wipe edit-modal state on logout (cfg/rawJson are cleared by vn-common).
    shared.onLogout(() => {
      ruleEditModal.show = false;
      editMatcherModal.show = false;
      configImportError.value = '';
      configImportOk.value = '';
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();