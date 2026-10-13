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
    // Pagination: the server ring holds up to AUDIT_LIMIT entries; we fetch all
    // of them and paginate client-side so the UI stays responsive at 1000 rows.
    const auditPage = ref(1);
    const AUDIT_PAGE_SIZE = 50;

    async function loadAudit() {
      const tok = gAudit.mark();
      auditError.value = '';
      auditPage.value = 1;
      try {
        let url = '/verynginx/audit?limit=' + shared.AUDIT_LIMIT;
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
    const fpEditModal = reactive({
      show: false, hash: '', name: '', category: 'scanner', action: 'block',
      kind: 'ja4', match_mode: 'exact', error: ''
    });

    // A JA4 "section A" is exactly 10 chars — resty/ja4.lua writes protocol(1) +
    // version(2) + sni(1) + cipher count(2) + ext count(2) + alpn(2) — and the
    // alpn pair is "00" when the client offers none, so both are [0-9a-z]. A
    // JA4H prefix is 12 (resty/ja4h.lua: method(2) + version(2) + cookie(1) +
    // referer(1) + header count(2) + lang(4)). A JA3 is a bare 32-char MD5.
    // The (_|$) anchor requires that section A is the WHOLE leading segment: an
    // MD5 whose first 10 hex chars happen to satisfy the classes is not a JA4.
    // Only used to PRE-FILL the 类型 select — the resolved kind is always sent
    // explicitly, so the server never has to re-infer it from the hash.
    const RE_JA4 = /^[a-z][0-9]{2}[a-z][0-9]{4}[0-9a-z]{2}(_|$)/;
    const RE_JA4H = /^[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{2}[0-9a-z]{4}(_|$)/;
    // Set once the operator picks 类型 by hand; until then the hash field keeps
    // re-guessing it as the operator pastes.
    let fpKindTouched = false;

    function fpInferKind(hash) {
      const h = (hash || '').trim().toLowerCase();
      if (RE_JA4.test(h)) return 'ja4';
      if (RE_JA4H.test(h)) return 'ja4h';
      return 'ja3';
    }

    // Entries persisted before the JA4 upgrade carry no "kind"/"match_mode";
    // the backend infers ja3/exact for those on load, so mirror that here
    // instead of rendering a blank cell.
    function fpKind(fp) { return (fp && fp.kind) || 'ja3'; }
    function fpMatchMode(fp) { return (fp && fp.match_mode) || 'exact'; }
    // "family" = the first 10 chars of a JA4/JA4H hash. JA3 has no such
    // section and the server rejects the mode for it.
    function fpFamily(fp) { return (fp && fp.hash ? String(fp.hash).slice(0, 10) : '') || '-'; }
    function fpFamilyAllowed(kind) { return kind === 'ja4' || kind === 'ja4h'; }

    function fpKindTitle(kind) {
      if (kind === 'ja4') return 'JA4：TLS ClientHello 的结构化指纹。排序后对 GREASE 随机值稳定、人可读，是当前的主信号。';
      if (kind === 'ja4h') return 'JA4H：JA4+ 的 HTTP 层指纹（请求方法/头顺序/Cookie）。默认关闭，需在 config.json 的 fingerprints.ja4.http_enable 打开。';
      if (kind === 'tls') return '协商协议|密码套件 回退值：标识的是「一条连接协商出了什么」，不是客户端，不可作为匹配项。';
      return 'JA3：ClientHello 要素的 MD5（32 位十六进制）。保留给已有的 JA3 指纹库，新条目建议改用 JA4。';
    }

    // Hash field input handler: keep 类型 in sync with what was pasted unless
    // the operator has already chosen one explicitly.
    function inferFpKind() {
      if (fpKindTouched) return;
      fpEditModal.kind = fpInferKind(fpEditModal.hash);
    }
    // 「类型」 is also what gates the family match mode — dropping back to
    // exact keeps the form in a state the backend will accept.
    function setFpEditKind(kind) {
      fpKindTouched = true;
      fpEditModal.kind = kind;
      if (!fpFamilyAllowed(kind)) fpEditModal.match_mode = 'exact';
    }

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
      fpEditModal.kind = 'ja4';
      fpEditModal.match_mode = 'exact';
      fpEditModal.error = '';
      fpKindTouched = false;
      fpEditModal.show = true;
    }

    // The server does the same checks (fingerprint_db.add) and returns its
    // message; reproducing them here just spares a doomed round-trip and keeps
    // the wording identical, so the operator sees one consistent explanation.
    function fpValidate(entry) {
      if (!entry.hash || !entry.name) return '哈希和名称必填';
      if (entry.match_mode === 'family') {
        if (!fpFamilyAllowed(entry.kind)) return 'family 匹配仅支持 JA4 / JA4H（JA3 无家族段）';
        if (entry.hash.length < 10) return 'family 匹配需要至少 10 个字符（JA4 家族段 a）';
      }
      return '';
    }

    async function saveFpAdd() {
      if (fpSaving.value) return;
      const entry = {
        hash: (fpEditModal.hash || '').trim(),
        name: (fpEditModal.name || '').trim(),
        kind: fpEditModal.kind || 'ja3',
        match_mode: fpEditModal.match_mode || 'exact',
        category: fpEditModal.category,
        action: fpEditModal.action
      };
      const bad = fpValidate(entry);
      if (bad) { fpEditModal.error = bad; showToast(bad, 'error'); return; }
      fpEditModal.error = '';
      fpSaving.value = true;
      try {
        const d = await api('POST', '/verynginx/fingerprints', entry);
        if (d.ret === 'success') {
          fpEditModal.show = false;
          showToast('指纹已添加', 'success');
          await loadFingerprints();
        } else {
          fpEditModal.error = d.message || '添加失败';
          showToast(fpEditModal.error, 'error');
        }
      } catch (e) {
        // 400/500 from the API layer — surface the server's own message.
        fpEditModal.error = e.message || '添加失败';
        showToast(fpEditModal.error, 'error');
      } finally {
        fpSaving.value = false;
      }
    }

    // Inline 「匹配」 dropdown. @change gives us the new value only, so the
    // previous mode is captured before mutating — a rejected save (e.g. family
    // on a ja3) snaps the row back instead of leaving a lie on screen.
    async function setFpMatchMode(fp, ev) {
      const sel = ev && ev.target;
      const next = sel ? sel.value : null;
      if (!next) return;
      const prev = fpMatchMode(fp);
      if (next === prev) return;
      if (next === 'family' && !fpFamilyAllowed(fpKind(fp))) {
        sel.value = prev;
        showToast('family 匹配仅支持 JA4 / JA4H（JA3 无家族段）', 'error');
        return;
      }
      fp.match_mode = next;
      if (await saveFp(fp)) return;
      fp.match_mode = prev;
      if (sel) sel.value = prev;
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
    // Pagination computed defined AFTER auditTbl so it can reference auditTbl.rows.
    const auditPagedRows = computed(() => {
      const rows = auditTbl.rows || [];
      const list = Array.isArray(rows) ? rows : [];
      const start = (auditPage.value - 1) * AUDIT_PAGE_SIZE;
      return list.slice(start, start + AUDIT_PAGE_SIZE);
    });
    const auditTotalPages = computed(() => {
      const rows = auditTbl.rows || [];
      const list = Array.isArray(rows) ? rows : [];
      return Math.max(1, Math.ceil(list.length / AUDIT_PAGE_SIZE));
    });
    view('auditPage', auditPage);
    view('auditTotalPages', auditTotalPages);
    view('auditPagedRows', auditPagedRows);
    view('AUDIT_PAGE_SIZE', AUDIT_PAGE_SIZE);
    view('auditError', auditError);
    view('loadAudit', loadAudit);
    view('clearAuditFilters', clearAuditFilters);
    view('setAuditSincePreset', setAuditSincePreset);
    view('auditActionClass', auditActionClass);
    // Reset page to 1 whenever client-side filter changes (the filter box
    // does not call loadAudit; it only filters the already-fetched rows).
    watch(() => auditTbl.state.filter, () => { auditPage.value = 1; });
    view('fingerprints', fingerprints);
    view('fpCategories', fpCategories);
    view('fpError', fpError);
    view('fpToggleBusy', fpToggleBusy);
    view('fpEditModal', fpEditModal);
    view('fpSaving', fpSaving);
    view('fpKind', fpKind);
    view('fpMatchMode', fpMatchMode);
    view('fpFamily', fpFamily);
    view('fpFamilyAllowed', fpFamilyAllowed);
    view('fpKindTitle', fpKindTitle);
    view('inferFpKind', inferFpKind);
    view('setFpEditKind', setFpEditKind);
    view('setFpMatchMode', setFpMatchMode);
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