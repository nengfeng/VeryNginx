// vn-advanced.js - Domain module for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    
    window.VN.modules['vnadvanced'] = function createvnadvancedModule(ctx) {
        const { expose, api, store, page, dashTab, advTab, loading, loginUser, loginPass, loginError, status, connHistory, cfg, healthData, overview, dictUsage, cfgTab, theme, rawJson, jsonError, jsonSaving, statsData, statsType, statsError, expandedUri, editMatcherModal, isValidIpLiteral, refreshCsrf, refreshCsrfOnce, csrfToken, showConfirm, confirmModal, confirmModalOk, confirmModalCancel, toastMsg, toastType, toastVisible } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;
        
    // ---- Audit State ----
    const auditEntries = ref([]);
        expose('auditEntries', auditEntries);
    const auditError = ref('');
        expose('auditError', auditError);
    // auditFilterUser/Action/Since/Until moved to vn-common.js (shared state)
    const { auditFilterUser, auditFilterAction, auditFilterSince, auditFilterUntil } = ctx;

    const plugins = ref([]);
        expose('plugins', plugins);
    const pluginsError = ref('');
        expose('pluginsError', pluginsError);
    const versionInfo = ref({ version: '', commit: '' });
        expose('versionInfo', versionInfo);
    // toastMsg/toastType/toastVisible/showToast provided by vn-common.js via ctx
    const configImportError = ref('');
        expose('configImportError', configImportError);
    const configImportOk = ref('');
        expose('configImportOk', configImportOk);
    const topPaths = ref([]);
        expose('topPaths', topPaths);


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
        
        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();