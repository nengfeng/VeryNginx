// vn-frequency.js - Frequency limiting module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-waf.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnfrequency'] = function createvnfrequencyModule(shared) {
        const { ctx, view, api, showToast, showConfirm, validateMatcherIps, asList } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Frequency Limit State ----
    const freqStats = ref([]);
    const freqRules = ref([]);
    const freqTemplates = ref([]);
    const freqTemplatesLoaded = ref(false);
    const freqError = ref('');
    const freqRuleModal = reactive({ show: false, mode: 'create', _matcherRef: null, id: '', key: 'ip', limit: 60, window: 60, code: 429, enable: true, matcherJson: '{}' });
    const freqTemplateModal = reactive({ show: false, name: '', label: '', description: '', id: '', key: 'ip', limit: 60, window: 60, code: 429, matcherJson: '{}' });

    // Stale-response guard for the frequency data loader.
    const gFreqData = shared.createStaleGuard();

    // ---- Load ----
    async function loadFrequencyData() {
      const tok = gFreqData.mark();
      try {
        const results = await Promise.allSettled([
          api('GET', '/verynginx/frequency/stats'),
          api('GET', '/verynginx/frequency/rules'),
          api('GET', '/verynginx/frequency/templates'),
        ]);
        if (!gFreqData.isCurrent(tok)) return;
        const [statsRes, rulesRes, tmplRes] = results.map(r => (r.status === 'fulfilled' ? r.value : null));
        if (statsRes && statsRes.ret === 'success') freqStats.value = asList(statsRes.data);
        if (rulesRes && rulesRes.ret === 'success') freqRules.value = asList(rulesRes.data);
        if (tmplRes && tmplRes.ret === 'success') freqTemplates.value = asList(tmplRes.data);
        freqTemplatesLoaded.value = true;
        const failures = results.filter(r => r.status === 'rejected').map(r => r.reason.message);
        if (failures.length) {
          console.warn('loadFrequencyData partial failure:', failures.join('; '));
          if (!failures.includes('session_expired')) freqError.value = '部分数据加载失败: ' + failures.join('; ');
        } else {
          freqError.value = '';
        }
      } catch (e) {
        if (!gFreqData.isCurrent(tok)) return;
        console.warn('loadFrequencyData failed:', e.message);
        freqTemplatesLoaded.value = true;
        if (e.message !== 'session_expired') freqError.value = '加载频率限制数据失败: ' + e.message;
      }
    }

    // ---- Templates ----
    async function previewFreqTemplate(name) {
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
      const rule = freqTemplateModal;
      if (!await showConfirm({
        title: '应用频率模板',
        message: `从模板 ${rule.label} 创建并下发限流规则？\n\n键=${rule.key} 限制=${rule.limit}/窗口=${rule.window}s 动作码=${rule.code}${freqMatcherSummary(rule.matcherJson)}`,
        type: 'primary',
      })) return;
      try {
        const overrides = {
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

    // ---- Rule CRUD ----
    function openFreqRuleCreate() {
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

    const freqRuleSaving = ref(false);
    async function saveFreqRule() {
      if (freqRuleSaving.value) return;
      freqRuleSaving.value = true;
      try {
        // Client-side validation
        if (!freqRuleModal.key || freqRuleModal.key.trim() === '') {
          showToast('限速键 (key) 不能为空', 'error'); return;
        }
        const limit = Number(freqRuleModal.limit);
        const window = Number(freqRuleModal.window);
        const code = Number(freqRuleModal.code);
        if (!limit || limit < 1) { showToast('限流阈值必须 >= 1', 'error'); return; }
        if (!window || window < 1) { showToast('时间窗口必须 >= 1 秒', 'error'); return; }
        if (!code || code < 100 || code > 599) { showToast('响应码必须是 100-599 之间的合法状态码', 'error'); return; }

        // A rule may reference a named matcher (_matcherRef) OR carry an inline
        // matcher (matcherJson). When editing a ref rule, the matcherJson box is
        // shown as a '{}' placeholder; if the user actually types a matcher
        // there, the inline value must win — otherwise the edit is silently
        // discarded and the limit scope won't match what they see.
        const mj = (freqRuleModal.matcherJson || '').trim();
        let finalMatcher;
        try {
          if (freqRuleModal._matcherRef && mj === '{}') {
            finalMatcher = freqRuleModal._matcherRef;
          } else if (mj && mj !== '{}') {
            finalMatcher = JSON.parse(mj);
            if (typeof finalMatcher !== 'object' || finalMatcher === null || Array.isArray(finalMatcher)) {
              showToast('匹配器必须是 JSON 对象, 如 {"IP": {"value": "1.2.3.4"}}', 'error');
              return;
            }
            const ipErr = validateMatcherIps(finalMatcher);
            if (ipErr) { showToast(ipErr, 'error'); return; }
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
        if (finalMatcher !== undefined) {
          rule.matcher = finalMatcher;
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
      } finally {
        freqRuleSaving.value = false;
      }
    }

    async function deleteFreqRule(rule) {
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

    // ---- Exports ----
    view('freqStats', freqStats);
    view('freqRules', freqRules);
    view('freqTemplates', freqTemplates);
    view('freqTemplatesLoaded', freqTemplatesLoaded);
    view('freqError', freqError);
    view('freqRuleModal', freqRuleModal);
    view('freqTemplateModal', freqTemplateModal);
    view('loadFrequencyData', loadFrequencyData);
    view('previewFreqTemplate', previewFreqTemplate);
    ctx('freqMatcherSummary', freqMatcherSummary);
    view('applyFreqTemplate', applyFreqTemplate);
    view('openFreqRuleCreate', openFreqRuleCreate);
    view('openFreqRuleEdit', openFreqRuleEdit);
    view('saveFreqRule', saveFreqRule);
    view('freqRuleSaving', freqRuleSaving);
    view('deleteFreqRule', deleteFreqRule);

    // Wipe per-session frequency data on logout.
    // Keyboard: Esc close + focus management for all dialogs.
    shared.bindModal(freqRuleModal, { label: '频率规则编辑器' });
    shared.bindModal(freqTemplateModal, { label: '模板应用对话框' });

    shared.onLogout(() => {
      freqStats.value = [];
      freqRules.value = [];
      freqTemplates.value = [];
      freqTemplatesLoaded.value = false;
      freqError.value = '';
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();