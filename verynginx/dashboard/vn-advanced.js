// vn-advanced.js - Advanced (audit/fingerprint/plugin) module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-reputation.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnadvanced'] = function createvnadvancedModule(shared) {
        const { ctx, view, api, showToast, showUndoToast, showConfirm, auditFilterUser, auditFilterAction, auditFilterSince, auditFilterUntil, asList } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Audit State ----
    const auditEntries = ref([]);
    const auditError = ref('');

    async function loadAudit() {
      const tok = gAudit.mark();
      auditError.value = '';
      try {
        let url = '/verynginx/audit?limit=500';
        if (auditFilterUser.value) url += '&user=' + encodeURIComponent(auditFilterUser.value);
        if (auditFilterAction.value) url += '&action=' + encodeURIComponent(auditFilterAction.value);
        if (auditFilterSince.value) {
          const sinceTs = Math.floor(new Date(auditFilterSince.value).getTime() / 1000);
          if (!Number.isNaN(sinceTs)) url += '&since=' + sinceTs;
        }
        if (auditFilterUntil.value) {
          const untilTs = Math.floor(new Date(auditFilterUntil.value).getTime() / 1000);
          if (!Number.isNaN(untilTs)) url += '&until=' + untilTs;
        }
        const d = await api('GET', url);
        if (!gAudit.isCurrent(tok)) return;
        if (d.ret === 'success') {
          auditEntries.value = asList(d.data);
        } else {
          auditError.value = d.message || '审计日志加载失败';
        }
      } catch (e) { if (gAudit.isCurrent(tok)) auditError.value = e.message; }
    }

    let auditClearGuard = false;
    function clearAuditFilters() {
      // Arm the guard only when a value will actually change — if the filters
      // are already empty the watcher never fires and an armed guard would
      // swallow the user's next legitimate edit.
      if (auditFilterUser.value || auditFilterAction.value || auditFilterSince.value || auditFilterUntil.value) {
        auditClearGuard = true;
      }
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
      if (auditFilterSince.value !== val) auditClearGuard = true;
      auditFilterSince.value = val;
      loadAudit();
    }

    let auditFilterTimer = null;
    watch([auditFilterUser, auditFilterAction, auditFilterSince, auditFilterUntil], () => {
      if (auditClearGuard) { auditClearGuard = false; return; }
      if (auditFilterTimer) clearTimeout(auditFilterTimer);
      auditFilterTimer = setTimeout(() => loadAudit(), 400);
    });

    // Clear a pending debounce on logout so it can't fire a loadAudit after
    // the session is gone.
    watch(() => shared.store.loggedIn, (v) => {
      if (!v && auditFilterTimer) { clearTimeout(auditFilterTimer); auditFilterTimer = null; }
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
    const fpSaving = ref(false);
    const fpEditModal = reactive({ show: false, hash: '', name: '', category: 'scanner', action: 'block' });

    // Stale-response guards for the audit / fingerprint list loaders.
    const gAudit = shared.createStaleGuard();
    const gFingerprints = shared.createStaleGuard();

    async function loadFingerprints() {
      const tok = gFingerprints.mark();
      try {
        const d = await api('GET', '/verynginx/fingerprints');
        if (!gFingerprints.isCurrent(tok)) return;
        if (d.ret === 'success') {
          fingerprints.value = asList(d.data);
          const cats = {};
          for (const fp of fingerprints.value) {
            if (fp.enabled) cats[fp.category] = (cats[fp.category] || 0) + 1;
          }
          fpCategories.value = cats;
        }
      } catch (e) {
        console.warn('loadFingerprints failed:', e.message);
        if (gFingerprints.isCurrent(tok) && e.message !== 'session_expired') fpError.value = '加载指纹失败: ' + e.message;
      }
    }

    function openFpAdd() {
      fpEditModal.hash = '';
      fpEditModal.name = '';
      fpEditModal.category = 'scanner';
      fpEditModal.action = 'block';
      fpEditModal.show = true;
    }

    async function saveFpAdd() {
      if (fpSaving.value) return;
      const hash = (fpEditModal.hash || '').trim();
      const name = (fpEditModal.name || '').trim();
      if (!hash || !name) { showToast('哈希和名称必填', 'error'); return; }
      fpSaving.value = true;
      try {
        const d = await api('POST', '/verynginx/fingerprints', {
          hash, name, category: fpEditModal.category, action: fpEditModal.action
        });
        if (d.ret === 'success') {
          fpEditModal.show = false;
          showToast('指纹已添加', 'success');
          await loadFingerprints();
        } else {
          showToast(d.message || '添加失败', 'error');
        }
      } catch (e) {
        showToast(e.message || '添加失败', 'error');
      } finally {
        fpSaving.value = false;
      }
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
        // The list items carry `enabled`; the server's fp.add() reads `enable`
        // (fingerprint_db.lua). Send the server's key or a disable is stored
        // as enabled=true and the checkbox snaps back on reload.
        const body = Object.assign({}, fp, { enable: fp.enabled !== false });
        delete body.enabled;
        const d = await api('PUT', '/verynginx/fingerprints', body);
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
      if (!await showConfirm({ title: '删除指纹', message: `删除指纹 "${fp.hash}"?\n\n删除后需在「添加」页手动重建才能恢复。`, type: 'danger' })) return;
      try {
        const d = await api('DELETE', '/verynginx/fingerprints/' + encodeURIComponent(fp.hash));
        if (d.ret === 'success') {
          if (d.removed === false) {
            showToast('指纹不存在（可能已被删除）: ' + fp.hash, 'error');
          } else {
            showUndoToast(`已删除指纹 "${fp.name || fp.hash.slice(0,8)}"`, async () => {
              // Fingerprint undo: re-add via API
              const entry = JSON.parse(JSON.stringify(fp));
              delete entry._removed;
              const r = await api('POST', '/verynginx/fingerprints', entry);
              if (r.ret === 'success') showToast('已撤销：恢复指纹', 'success');
              else throw new Error(r.message || '恢复失败');
              await loadFingerprints();
            });
          }
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
          plugins.value = asList(d.data);
        } else {
          pluginsError.value = d.message || '插件列表加载失败';
        }
      } catch (e) {
        pluginsError.value = e.message;
      }
    }

    const pluginBusy = reactive(new Set());
    async function togglePlugin(p) {
      if (pluginBusy.has(p.name)) return;
      pluginBusy.add(p.name);
      pluginsError.value = '';
      const old = p.enable;
      p.enable = !p.enable;
      try {
        const d = await api('POST', '/verynginx/plugins/' + encodeURIComponent(p.name) + '/toggle');
        if (d.ret === 'success') {
          p.enable = d.data.enable;
          if (p.enable !== !old) loadPlugins();
          showToast(p.enable ? '已启用 ' + p.name : '已停用 ' + p.name, p.enable ? 'success' : 'info');
        } else {
          p.enable = old;
          pluginsError.value = d.message || '切换失败';
        }
      } catch (e) {
        p.enable = old;
        pluginsError.value = e.message;
      } finally {
        pluginBusy.delete(p.name);
      }
    }

    // ---- Exports ----
    view('auditEntries', auditEntries);
    const auditTbl = shared.createTableTools(auditEntries);
    view('auditTbl', auditTbl);
    view('auditError', auditError);
    view('loadAudit', loadAudit);
    view('clearAuditFilters', clearAuditFilters);
    view('setAuditSincePreset', setAuditSincePreset);
    view('auditActionClass', auditActionClass);
    view('fingerprints', fingerprints);
    view('fpCategories', fpCategories);
    view('fpError', fpError);
    view('fpToggleBusy', fpToggleBusy);
    view('fpEditModal', fpEditModal);
    view('fpSaving', fpSaving);
    view('loadFingerprints', loadFingerprints);
    view('openFpAdd', openFpAdd);
    view('saveFpAdd', saveFpAdd);
    view('toggleFp', toggleFp);
    ctx('saveFp', saveFp);
    view('deleteFp', deleteFp);
    view('plugins', plugins);
    view('pluginsError', pluginsError);
    view('pluginBusy', pluginBusy);
    view('loadPlugins', loadPlugins);
    view('togglePlugin', togglePlugin);

    // Wipe per-session data on logout so a re-login as another account
    // doesn't flash the previous session's audit/fingerprint records.
    // Keyboard: Esc close + focus management for all dialogs.
    shared.bindModal(fpEditModal, { label: '指纹编辑器' });

    shared.onLogout(() => {
      auditEntries.value = [];
      auditError.value = '';
      fingerprints.value = [];
      fpCategories.value = {};
      fpError.value = '';
      plugins.value = [];
      pluginsError.value = '';
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();