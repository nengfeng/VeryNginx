// vn-frequency.js - Domain module for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    
    window.VN.modules['vnfrequency'] = function createvnfrequencyModule(ctx) {
        const { expose, api, store, page, dashTab, advTab, loading, loginUser, loginPass, loginError, status, connHistory, cfg, healthData, overview, dictUsage, cfgTab, theme, rawJson, jsonError, jsonSaving, statsData, statsType, statsError, expandedUri, editMatcherModal, isValidIpLiteral, refreshCsrf, refreshCsrfOnce, csrfToken, showToast, showConfirm, confirmModal, confirmModalOk, confirmModalCancel, toastMsg, toastType, toastVisible } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;
        
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
        
        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();