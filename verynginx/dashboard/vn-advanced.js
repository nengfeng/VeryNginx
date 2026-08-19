// vn-advanced.js - Advanced (audit/fingerprint/plugin) module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-reputation.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnadvanced'] = function createvnadvancedModule(ctx) {
        const { expose, api, showToast, showConfirm, auditFilterUser, auditFilterAction, auditFilterSince, auditFilterUntil } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Audit State ----
    const auditEntries = ref([]);
    const auditError = ref('');

    async function loadAudit() {
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
      auditClearGuard = true;
      if (auditFilterTimer) { clearTimeout(auditFilterTimer); auditFilterTimer = null; }
      auditFilterUser.value = '';
      auditFilterAction.value = '';
      auditFilterSince.value = '';
      auditFilterUntil.value = '';
      loadAudit();
    }

    function setAuditSincePreset(preset) {
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

    function auditActionClass(a) {
      if (!a) return '';
      if (a.startsWith('login')) return a === 'login_success' ? 'tag-ok' : 'tag-err';
      if (a.startsWith('waf_rule')) return 'tag-warn';
      if (a === 'POST' || a === 'PUT' || a === 'DELETE') return 'tag-warn';
      return '';
    }


    // ---- Fingerprints ----
    const fingerprints = ref([]);
    const fpCategories = ref({});
    const fpError = ref('');
    const fpToggleBusy = ref(false);
    const fpEditModal = reactive({ show: false, hash: '', name: '', category: 'scanner', action: 'block' });

    async function loadFingerprints() {
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
      fpEditModal.hash = '';
      fpEditModal.name = '';
      fpEditModal.category = 'scanner';
      fpEditModal.action = 'block';
      fpEditModal.show = true;
    }

    async function toggleFp(fp) {
      fpToggleBusy.value = true;
      const old = fp.enabled;
      fp.enabled = !old;
      try {
        const ok = await saveFp(fp);
        if (!ok) fp.enabled = old;
      } finally {
        fpToggleBusy.value = false;
      }
    }

    async function saveFp(fp) {
      try {
        const d = await api('PUT', '/verynginx/fingerprints', fp);
        if (d.ret === 'success') {
          await loadFingerprints();
          return true;
        } else {
          showToast(d.message || '保存失败', 'error');
        }
      } catch (e) {
        showToast(e.message || '保存失败', 'error');
      }
      return false;
    }

    async function deleteFp(fp) {
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
    const plugins = ref([]);
    const pluginsError = ref('');

    async function loadPlugins() {
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

    // ---- Exports ----
    expose('auditEntries', auditEntries);
    expose('auditError', auditError);
    expose('loadAudit', loadAudit);
    expose('clearAuditFilters', clearAuditFilters);
    expose('setAuditSincePreset', setAuditSincePreset);
    expose('auditActionClass', auditActionClass);
    expose('fingerprints', fingerprints);
    expose('fpCategories', fpCategories);
    expose('fpError', fpError);
    expose('fpToggleBusy', fpToggleBusy);
    expose('fpEditModal', fpEditModal);
    expose('loadFingerprints', loadFingerprints);
    expose('openFpAdd', openFpAdd);
    expose('toggleFp', toggleFp);
    expose('saveFp', saveFp);
    expose('deleteFp', deleteFp);
    expose('plugins', plugins);
    expose('pluginsError', pluginsError);
    expose('loadPlugins', loadPlugins);
    expose('togglePlugin', togglePlugin);

        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();