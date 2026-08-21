// vn-common.js - Shared state + core utilities for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded FIRST.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vncommon'] = function createvncommonModule(shared) {
        const { ctx, view } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // Module-level store so api() can access it for session expiration handling
    let store = reactive({ loggedIn: false, user: null });
    view('store', store);

    // ---- API ----
    let csrfToken = null;

    // Strict IP literal validation (IPv4 0-255 per octet, IPv6 with optional /prefix).
    // Mirrors core/ip_reputation.lua validate_whitelist_entry semantics on the
    // client side: /0 rejected, IPv4 CIDR must not have host bits set
    // (1.2.3.4/24 is ambiguous and the server rejects it).
    function isValidIpLiteral(ip, allowPrefix) {
      if (!ip || typeof ip !== 'string') return false;
      const s = ip.trim();
      if (!s) return false;
      if (s.includes(':')) {
        // IPv6 literal (optionally with /<prefix>)
        const body = allowPrefix ? s.split('/')[0] : s;
        if (!/^[0-9a-fA-F:]+$/.test(body) || !body.includes(':')) return false;
        if (allowPrefix && s.includes('/')) {
          const p = Number(s.split('/')[1]);
          if (!Number.isInteger(p) || p < 1 || p > 128) return false;
        }
        return true;
      }
      // IPv4 literal (optionally with /<prefix>)
      const body = allowPrefix ? s.split('/')[0] : s;
      const parts = body.split('.');
      if (parts.length !== 4) return false;
      let num = 0;
      for (const p of parts) {
        if (!/^\d+$/.test(p)) return false;
        const n = Number(p);
        if (n < 0 || n > 255) return false;
        if (p.length > 1 && p[0] === '0') return false; // no leading zeros
        num = num * 256 + n;
      }
      if (allowPrefix && s.includes('/')) {
        const p = Number(s.split('/')[1]);
        if (!Number.isInteger(p) || p < 1 || p > 32) return false;
        // Host bits must be zero (network address form)
        const mask = (2 ** (32 - p)) - 1;
        if ((num & mask) !== 0) return false;
      }
      return true;
    }

    // Recursively validate any matcher IP value. Match conditions that carry
    // an "IP" key (string value, or {value: "..."}) are checked against
    // isValidIpLiteral — bare IPs only: the matcher engine compares strings
    // and has no CIDR semantics, so a CIDR would silently never match.
    // Returns an error string or null. Traverses arrays and nested objects.
    function validateMatcherIps(node, trail) {
      trail = trail || '';
      if (node == null || typeof node !== 'object') return null;
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i++) {
          const e = validateMatcherIps(node[i], trail + '[' + i + ']');
          if (e) return e;
        }
        return null;
      }
      for (const k in node) {
        const v = node[k];
        if (k === 'IP') {
          const val = (typeof v === 'string') ? v : (v && typeof v.value === 'string' ? v.value : null);
          if (val != null && !isValidIpLiteral(val, false)) {
            return '匹配器 IP 值无效: ' + val + '（位于 ' + (trail ? trail + '.' : '') + 'IP）';
          }
        } else if (typeof v === 'object') {
          const e = validateMatcherIps(v, trail ? trail + '.' + k : k);
          if (e) return e;
        }
      }
      return null;
    }
    ctx('validateMatcherIps', validateMatcherIps);

    // Session-expired errors are raised by api() on 401/403 and already
    // handled centrally (store.loggedIn=false -> login page). Swallow them at
    // the global level so timer-driven refreshes (loadStatus every 3s, etc.)
    // don't produce unhandled Promise rejections / console noise.
    window.addEventListener('unhandledrejection', (ev) => {
      const reason = ev && ev.reason;
      if (reason && reason.message === 'session_expired') {
        ev.preventDefault();
      }
    });

    async function api(method, path, body, opts2) {
      async function doFetch() {
        const opts = { method, credentials: 'same-origin' };
        if (body) {
          if (body instanceof URLSearchParams) {
            opts.body = body;
          } else if (typeof body === 'object' && !(body instanceof FormData)) {
            opts.headers = { 'Content-Type': 'application/json' };
            opts.body = JSON.stringify(body);
          } else {
            opts.body = body;
          }
        }
        if (method !== 'GET' && csrfToken) {
          opts.headers = opts.headers || {};
          opts.headers['X-CSRF-Token'] = csrfToken;
        }
        return await fetch(path, opts);
      }

      function parseError(res) {
        return res.text().catch(() => '').then((text) => {
          let msg;
          try { const j = JSON.parse(text); msg = j.message || j.err || text; } catch { msg = text || `HTTP ${res.status}`; }
          return msg;
        });
      }

      let res = await doFetch();

      // 401 = authentication problem. This can be a genuinely expired session,
      // OR a stale CSRF token (e.g. after a server restart dropped the
      // server-side CSRF state while the stateless HMAC session is still
      // valid). Self-heal once: refresh the CSRF token and retry. If the
      // refresh itself fails (401), the session is truly gone.
      if (res.status === 401 && path !== '/verynginx/login' && path !== '/verynginx/csrf') {
        const refreshed = await refreshCsrf();
        if (refreshed) {
          res = await doFetch();
        } else {
          csrfToken = null;
          store.loggedIn = false;
          store.user = null;
          sessionExpiredNotice.value = true;
          throw new Error('session_expired');
        }
      }

      if (res.status === 401 && path !== '/verynginx/login') {
        csrfToken = null;
        store.loggedIn = false;
        store.user = null;
        sessionExpiredNotice.value = true;
        throw new Error('session_expired');
      }

      // 403 = operation forbidden (e.g. whitelisted IP). This is NOT an auth
      // failure — keep the session alive and surface the server's message.
      if (res.status === 403 && path !== '/verynginx/login') {
        throw new Error(await parseError(res));
      }

      if (!res.ok) {
        throw new Error(await parseError(res));
      }
      if (opts2 && opts2.text) return res.text();
      return res.json();
    }

    async function refreshCsrf() {
      try {
        const d = await fetch('/verynginx/csrf', { method: 'GET', credentials: 'same-origin' });
        if (d.ok) {
          const j = await d.json();
          csrfToken = j.csrf_token;
          return true;
        } else {
          return false;
        }
      } catch (e) {
        return false;
      }
    }

    async function refreshCsrfOnce() {
      if (csrfToken) return true;
      return await refreshCsrf();
    }

    // ===== Shared UI utilities (toast, confirm modal) =====

    // Toast queue. Tiered auto-dismiss: success/info stay short, warnings a
    // bit longer, errors are sticky (manual close only) so a save failure
    // can't be displaced by the next poller's success toast before it's read.
    // The list is capped — a flapping poller erroring every 3s must not grow
    // the stack without bound.
    const toasts = ref([]);
    let toastSeq = 0;
    const TOAST_DURATION = { success: 2500, info: 3000, warning: 6000, error: 0 }; // 0 = sticky
    const TOAST_MAX = 5;

    function showToast(msg, type) {
      const t = type || 'info';
      // Dedup consecutive identical messages — a poller erroring every 3s
      // must not fill the sticky stack with copies of one failure.
      const last = toasts.value[toasts.value.length - 1];
      if (last && last.type === t && last.msg === String(msg)) return;
      const item = { id: ++toastSeq, msg: String(msg), type: t, timer: null };
      toasts.value.push(item);
      while (toasts.value.length > TOAST_MAX) {
        const dropped = toasts.value.shift();
        if (dropped.timer) clearTimeout(dropped.timer);
      }
      const dur = TOAST_DURATION[t] === undefined ? 3000 : TOAST_DURATION[t];
      if (dur > 0) item.timer = setTimeout(() => dismissToast(item.id), dur);
    }
    ctx('showToast', showToast);

    function dismissToast(id) {
      const i = toasts.value.findIndex(t => t.id === id);
      if (i >= 0) {
        const t = toasts.value[i];
        if (t.timer) clearTimeout(t.timer);
        toasts.value.splice(i, 1);
      }
    }
    view('toasts', toasts);
    view('dismissToast', dismissToast);

    const confirmModal = reactive({
      show: false,
      title: '',
      message: '',
      type: 'danger',
      requireInput: false,
      inputLabel: '',
      inputValue: '',
      inputExpected: '',
    });
    view('confirmModal', confirmModal);

    // A queue so overlapping showConfirm() calls don't clobber each other's
    // pending Promise (the old single-resolve design let a second confirm
    // overwrite the first's resolver, orphaning it).
    let confirmQueue = [];

    function renderConfirm() {
      const top = confirmQueue[0];
      if (!top) { confirmModal.show = false; return; }
      const o = top.opts;
      confirmModal.title = o.title || '';
      confirmModal.message = o.message || '';
      confirmModal.type = o.type || 'danger';
      confirmModal.requireInput = !!o.requireInput;
      confirmModal.inputLabel = o.inputLabel || '';
      confirmModal.inputExpected = o.inputExpected || '';
      confirmModal.inputValue = '';
      confirmModal.show = true;
    }

    function closeConfirm(res) {
      const top = confirmQueue.shift();
      confirmModal.show = false;
      if (top) top.resolve(res);
      if (confirmQueue.length) renderConfirm();
    }

    function showConfirm(opts) {
      return new Promise((resolve) => {
        confirmQueue.push({ opts, resolve });
        if (confirmQueue.length === 1) renderConfirm();
      });
    }
    ctx('showConfirm', showConfirm);

    function confirmModalOk() {
      if (confirmModal.requireInput) {
        if (confirmModal.inputValue.trim() !== confirmModal.inputExpected.trim()) {
          showToast('确认文本不匹配', 'error');
          return;
        }
      }
      closeConfirm(true);
    }
    view('confirmModalOk', confirmModalOk);

    function confirmModalCancel() {
      closeConfirm(false);
    }
    view('confirmModalCancel', confirmModalCancel);

    // Safety net: resolve any confirm closed without going through
    // confirmModalOk/Cancel (e.g. a future direct `show = false`) as "false".
    // Normal closes are already shifted+resolved by closeConfirm, leaving the
    // queue empty so this watcher is a no-op for them.
    watch(() => confirmModal.show, (show) => {
      if (!show && confirmQueue.length) closeConfirm(false);
    });

    // Escape closes the topmost queued confirm as "false". Its typed input is
    // a confirmation phrase, not editor content — exclude from dirty tracking.
    bindModal(confirmModal, { onClose: () => closeConfirm(false), trackInput: false });

    // ===== Shared navigation state =====
    const page = ref('dashboard');
    view('page', page);
    const dashTab = ref('overview');
    view('dashTab', dashTab);
    const advTab = ref('fingerprints');
    view('advTab', advTab);
    const cfgTab = ref('system');
    view('cfgTab', cfgTab);
    const theme = ref(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
    view('theme', theme);

    function toggleTheme() {
      const newTheme = theme.value === 'dark' ? 'light' : 'dark';
      theme.value = newTheme;
      document.documentElement.setAttribute('data-theme', newTheme);
      try { localStorage.setItem('vn_theme', newTheme); } catch(e) {}
    }
    view('toggleTheme', toggleTheme);

    // ===== Shared data state (populated by domain modules) =====
    const loading = ref(false);
    view('loading', loading);
    const loginUser = ref('');
    view('loginUser', loginUser);
    const loginPass = ref('');
    view('loginPass', loginPass);
    const loginError = ref('');
    view('loginError', loginError);
    // One-shot flag: set when api() force-ends the session (401 self-heal
    // failed), shown as a notice on the login page so an involuntary kick
    // isn't silent. Cleared on the next successful login.
    const sessionExpiredNotice = ref(false);
    view('sessionExpiredNotice', sessionExpiredNotice);
    const status = ref({});
    ctx('status', status);
    const connHistory = ref([]);
    view('connHistory', connHistory);
    const cfg = ref({});
    view('cfg', cfg);
    const healthData = ref({});
    view('healthData', healthData);
    const overview = ref({});
    view('overview', overview);
    const dictUsage = ref([]);
    view('dictUsage', dictUsage);
    const rawJson = ref('');
    view('rawJson', rawJson);
    // Set by the JSON editor textarea's @input; cleared whenever loadConfig()
    // re-syncs the textarea from saved state (load/save/import paths).
    const jsonDirty = ref(false);
    view('jsonDirty', jsonDirty);
    const jsonError = ref('');
    view('jsonError', jsonError);
    watch(rawJson, (val) => {
      jsonError.value = '';
      if (!val) return;
      try { JSON.parse(val); } catch (e) { jsonError.value = 'JSON: ' + e.message; }
    });
    const jsonSaving = ref(false);
    view('jsonSaving', jsonSaving);
    const statsData = ref(null);
    view('statsData', statsData);
    const statsType = ref('long');
    view('statsType', statsType);
    const statsError = ref('');
    view('statsError', statsError);
    const expandedUri = ref(null);
    view('expandedUri', expandedUri);
    const editMatcherModal = reactive({ show: false, name: '', conditions: '' });
    view('editMatcherModal', editMatcherModal);

    // versionInfo / topPaths are shared between dashboard (loader) and other
    // modules (advanced/about). Owned here to avoid load-order coupling.
    const versionInfo = ref({ version: '', commit: '' });
    view('versionInfo', versionInfo);
    const topPaths = ref([]);
    view('topPaths', topPaths);

    // Shared audit filter state (used by advanced/audit module)
    const auditFilterUser = ref('');
    view('auditFilterUser', auditFilterUser);
    const auditFilterAction = ref('');
    view('auditFilterAction', auditFilterAction);
    const auditFilterSince = ref('');
    view('auditFilterSince', auditFilterSince);
    const auditFilterUntil = ref('');
    view('auditFilterUntil', auditFilterUntil);

    // Expose core utilities
    ctx('api', api);
    ctx('isValidIpLiteral', isValidIpLiteral);
    ctx('refreshCsrf', refreshCsrf);
    ctx('refreshCsrfOnce', refreshCsrfOnce);
    ctx('csrfToken', () => csrfToken); // getter for current token
    ctx('clearCsrf', () => { csrfToken = null; });

    // ---- Polling registry ----
    // Refresh transparency: pause switch + per-poll last-run timestamps. The
    // badge computes "最后更新 N 秒前" from the newest stamp; a 1s ticker
    // re-renders the label without touching any data ref.
    const autoRefreshPaused = ref(false);
    view('autoRefreshPaused', autoRefreshPaused);
    const lastUpdated = {};
    const nowTick = ref(Date.now());
    setInterval(() => { nowTick.value = Date.now(); }, 1000);
    const lastRefreshLabel = computed(() => {
        let newest = 0;
        for (const t of Object.values(lastUpdated)) { if (t > newest) newest = t; }
        if (!newest || !store.loggedIn) return '';
        const sec = Math.max(0, Math.floor((nowTick.value - newest) / 1000));
        return sec < 5 ? '刚刚更新' : '最后更新 ' + sec + ' 秒前';
    });
    view('lastRefreshLabel', lastRefreshLabel);
    function toggleAutoRefresh() {
        autoRefreshPaused.value = !autoRefreshPaused.value;
        syncPolls();
    }
    view('toggleAutoRefresh', toggleAutoRefresh);

    // Central lifecycle for every auto-refresh poller. Each poller declares an
    // `active()` predicate; syncPolls() reconciles start/stop on navigation.
    // Pollers MUST register here instead of wiring ad-hoc per-page watches -
    // ad-hoc clear logic is how the status/overview/health timer leak crept in.
    const polls = new Map();

    function registerPoll(name, spec) {
        if (polls.has(name)) {
            const msg = 'Duplicate poll registration: ' + name;
            console.error('[VeryNginx] ' + msg);
            if (window.VN && window.VN._dups) window.VN._dups.push(msg);
            return;
        }
        polls.set(name, {
            name,
            active: spec.active,
            interval: spec.interval,
            load: spec.load,
            timer: null,
        });
    }

    function syncPolls() {
        if (!store.loggedIn) { stopAllPolls(); return; }
        // User pause switch (demo/troubleshooting): no poller may run while set.
        if (autoRefreshPaused.value) { stopAllPolls(); return; }
        for (const poll of polls.values()) {
            const shouldRun = poll.active();
            if (shouldRun && poll.timer === null) {
                runPollLoad(poll);
                poll.timer = setInterval(() => runPollLoad(poll), poll.interval);
            } else if (!shouldRun && poll.timer !== null) {
                clearInterval(poll.timer);
                poll.timer = null;
            }
        }
    }

    function runPollLoad(poll) {
        try {
            Promise.resolve(poll.load()).catch((e) => {
                console.error('[VeryNginx] poll load failed: ' + e.message);
            }).finally(() => {
                // Record freshness regardless of success — the badge shows how
                // long ago the backend was last ASKED, which is what "how
                // stale is this view" means during an outage.
                lastUpdated[poll.name] = Date.now();
            });
        } catch (e) {
            console.error('[VeryNginx] poll load failed: ' + e.message);
        }
    }

    function stopAllPolls() {
        for (const poll of polls.values()) {
            if (poll.timer !== null) {
                clearInterval(poll.timer);
                poll.timer = null;
            }
        }
    }

    ctx('registerPoll', registerPoll);
    ctx('syncPolls', syncPolls);
    ctx('stopAllPolls', stopAllPolls);

    // ---- Global navigation ----
    // Central navigation handler — all topnav links use this.
    // Data loading is explicit per-page; pages not listed rely on watches
    // (dashboard → syncPolls/stats, config → vn-config watch, advanced → vn-dashboard watch).
    // Cross-module functions are late-bound via shared to avoid load-order coupling.
    async function navigateTo(newPage) {
      // Unsaved-change guard across every editor (KB form, rule/matcher/WAF
      // editors via modal input tracking, JSON editor). Confirm -> discard.
      const unsaved = collectUnsaved();
      if (unsaved.length) {
        if (!await showConfirm({
          title: '未保存的更改',
          message: `${unsaved.join('、')}有未保存的更改，离开将丢失。确定放弃并离开？`,
          type: 'warning',
        })) return;
        discardUnsaved();
      }
      page.value = newPage;
      // Per-page data loading
      if (newPage === 'waf') { if (shared.loadWafData) await shared.loadWafData(); }
      else if (newPage === 'frequency') { if (shared.loadFrequencyData) await shared.loadFrequencyData(); }
      else if (newPage === 'reputation') { if (shared.loadRepData) await shared.loadRepData(); }
      else if (newPage === 'geoip') { if (shared.loadGeoIP) await shared.loadGeoIP(); if (shared.loadGeoIPStatus) await shared.loadGeoIPStatus(); }
      else if (newPage === 'kb') { if (shared.loadKbData) await shared.loadKbData(); }
    }
    view('navigateTo', navigateTo);

    // ---- Unsaved-change guard registry ----
    // Non-modal editors (KB settings form, config JSON textarea) register a
    // {label, isDirty, discard} triple; modal editors are tracked automatically
    // by bindModal() via delegated input listeners. collectUnsaved() feeds both
    // the in-app navigation guard and the beforeunload safety net.
    const dirtyGuards = [];
    function registerDirtyGuard(label, isDirty, discard) {
      dirtyGuards.push({ label, isDirty, discard });
    }
    ctx('registerDirtyGuard', registerDirtyGuard);

    function collectUnsaved() {
      const labels = [];
      for (const g of dirtyGuards) {
        let d = false;
        try { d = !!g.isDirty(); } catch (_) { /* treat as clean */ }
        if (d) labels.push(g.label);
      }
      for (const en of modalStack) {
        if (en.dirty && en.label) labels.push(en.label);
      }
      return labels;
    }
    ctx('collectUnsaved', collectUnsaved);

    function discardUnsaved() {
      for (const g of dirtyGuards) {
        let d = false;
        try { d = !!g.isDirty(); } catch (_) { /* already clean */ }
        if (d) { try { g.discard(); } catch (_) { /* keep going */ } }
      }
      for (const en of modalStack) {
        if (en.dirty) en.modal.show = false;
      }
    }

    window.addEventListener('beforeunload', (e) => {
      if (!collectUnsaved().length) return;
      e.preventDefault();
      e.returnValue = '';
    });

    registerDirtyGuard('配置 JSON 编辑器',
      () => jsonDirty.value,
      () => { rawJson.value = JSON.stringify(cfg.value || {}, null, 2); jsonDirty.value = false; });

    // ---- Logout hooks ----
    // Modules register a callback here so that logging out can wipe their
    // per-session data (otherwise a re-login as a different account flashes
    // the previous session's records). doLogout() calls runLogoutHooks().
    const logoutHooks = [];
    function onLogout(cb) { if (typeof cb === 'function') logoutHooks.push(cb); }
    ctx('onLogout', onLogout);
    function runLogoutHooks() {
      for (const cb of logoutHooks) {
        try { cb(); } catch (e) { console.error('[VeryNginx] logout hook failed', e); }
      }
    }
    ctx('runLogoutHooks', runLogoutHooks);

    // ---- Stale-response guard ----
    // Returns a guard for one resource. Call mark() before an async fetch and
    // isCurrent(token) after it; if a newer request started in the meantime the
    // older response is ignored (prevents slow out-of-order responses from
    // overwriting fresh state when the user switches filters/pages quickly).
    function createStaleGuard() {
      let n = 0;
      return {
        mark: () => ++n,
        isCurrent: (t) => t === n,
      };
    }
    ctx('createStaleGuard', createStaleGuard);

    // ---- Table sort/filter toolkit ----
    // Client-side instant filter + click-to-sort over the rows already loaded
    // (server-paginated tables therefore sort/filter within the current page).
    // Expose one instance per table as a single view() binding and use it from
    // the template as: v-model="t.state.filter", v-for="r in t.rows",
    // th @click="t.sortBy('col')". A third click on the same column clears
    // sorting; nulls always sort last.
    function createTableTools(sourceRef) {
      const state = reactive({ sortKey: '', sortDir: 1, filter: '' });
      const rows = computed(() => {
        let list = (sourceRef && sourceRef.value) || [];
        const q = state.filter.trim().toLowerCase();
        if (q) list = list.filter(r => JSON.stringify(r).toLowerCase().includes(q));
        if (!state.sortKey) return list;
        const k = state.sortKey;
        const dir = state.sortDir;
        return [...list].sort((a, b) => {
          const va = a ? a[k] : undefined;
          const vb = b ? b[k] : undefined;
          if (va == null && vb == null) return 0;
          if (va == null || vb == null) return va == null ? 1 : -1;
          if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir;
          return String(va).localeCompare(String(vb)) * dir;
        });
      });
      function sortBy(key) {
        if (state.sortKey === key) {
          if (state.sortDir === 1) { state.sortDir = -1; }
          else { state.sortKey = ''; state.sortDir = 1; }
        } else {
          state.sortKey = key;
          state.sortDir = 1;
        }
      }
      return { state, rows, sortBy };
    }
    ctx('createTableTools', createTableTools);

    // ---- Clipboard ----
    // Clipboard API requires a secure context; fall back to a temporary
    // textarea + execCommand for plain-http deployments.
    async function copyText(text) {
      const s = String(text == null ? '' : text);
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(s);
          showToast('已复制到剪贴板', 'success');
          return true;
        }
      } catch (e) { /* fall through to legacy path */ }
      try {
        const ta = document.createElement('textarea');
        ta.value = s;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        showToast(ok ? '已复制到剪贴板' : '复制失败', ok ? 'success' : 'error');
        return ok;
      } catch (e) {
        showToast('复制失败', 'error');
        return false;
      }
    }
    view('copyText', copyText);

    // ---- Modal keyboard accessibility ----
    // One composable for every dialog: Escape closes the topmost modal, focus
    // moves to its first field on open and returns to the opener on close,
    // and Tab is trapped inside the dialog so it can't wander to the page
    // behind it. Modals register via bindModal(modal[, {onClose}]); the stack
    // handles confirm-over-modal nesting.
    const modalStack = [];

    function modalFocusable(el) {
      return Array.from(el.querySelectorAll(
        'input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )).filter(x => x.offsetWidth > 0 || x.offsetHeight > 0);
    }

    function topModalOverlay() {
      const overlays = document.querySelectorAll('.modal-overlay');
      return overlays.length ? overlays[overlays.length - 1] : null;
    }

    window.addEventListener('keydown', (e) => {
      if (!modalStack.length) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        const top = modalStack[modalStack.length - 1];
        if (top.onClose) top.onClose();
        else top.modal.show = false;
      } else if (e.key === 'Tab') {
        const overlay = topModalOverlay();
        if (!overlay) return;
        const items = modalFocusable(overlay);
        if (!items.length) { e.preventDefault(); return; }
        const first = items[0];
        const last = items[items.length - 1];
        if (!overlay.contains(document.activeElement)) {
          e.preventDefault();
          first.focus();
        } else if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    });

    function bindModal(modal, opts) {
      opts = opts || {};
      watch(() => modal.show, (show) => {
        if (show) {
          const entry = { modal, onClose: opts.onClose, prevFocus: document.activeElement, dirty: false, label: opts.label || '', handlers: null };
          modalStack.push(entry);
          Vue.nextTick(() => {
            const overlay = topModalOverlay();
            if (!overlay) return;
            // Track user edits inside this dialog so the navigation guard can
            // warn before discarding half-filled forms. Confirm dialogs opt
            // out (their input is a typed confirmation, not content).
            if (opts.trackInput !== false) {
              entry.handlers = {
                input: () => { entry.dirty = true; },
                change: () => { entry.dirty = true; },
              };
              overlay.addEventListener('input', entry.handlers.input);
              overlay.addEventListener('change', entry.handlers.change);
            }
            if (overlay.contains(document.activeElement)) return;
            const target = overlay.querySelector('input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled])');
            if (target) target.focus();
          });
        } else {
          const idx = modalStack.findIndex(en => en.modal === modal);
          if (idx >= 0) {
            const entry = modalStack.splice(idx, 1)[0];
            if (entry.handlers) {
              const overlay = topModalOverlay();
              if (overlay) {
                overlay.removeEventListener('input', entry.handlers.input);
                overlay.removeEventListener('change', entry.handlers.change);
              }
            }
            try {
              if (entry.prevFocus && document.body.contains(entry.prevFocus)) entry.prevFocus.focus();
            } catch (_) { /* detached element */ }
          }
        }
      });
    }
    ctx('bindModal', bindModal);

    // vn-common owns the shared dashboard/config state — clear it on logout.
    onLogout(() => {
      status.value = {};
      connHistory.value = [];
      cfg.value = {};
      rawJson.value = '';
      healthData.value = {};
      overview.value = {};
      dictUsage.value = [];
      statsData.value = null;
      versionInfo.value = { version: '', commit: '' };
      topPaths.value = [];
      // Audit filters shape the next session's audit view — reset them so a
      // different account doesn't inherit the previous session's filter.
      auditFilterUser.value = '';
      auditFilterAction.value = '';
      auditFilterSince.value = '';
      auditFilterUntil.value = '';
      // Sticky error toasts from the old session must not linger on the
      // login page of the next one.
      for (const t of toasts.value) { if (t.timer) clearTimeout(t.timer); }
      toasts.value = [];
      // Freshness stamps from the previous session would render a bogus
      // "最后更新" right after re-login.
      for (const k of Object.keys(lastUpdated)) delete lastUpdated[k];
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();