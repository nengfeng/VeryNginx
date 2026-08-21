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
          throw new Error('session_expired');
        }
      }

      if (res.status === 401 && path !== '/verynginx/login') {
        csrfToken = null;
        store.loggedIn = false;
        store.user = null;
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

    const toastMsg = ref('');
    const toastType = ref('info');
    const toastVisible = ref(false);
    let toastTimer = null;

    function showToast(msg, type) {
      toastMsg.value = msg;
      toastType.value = type || 'info';
      toastVisible.value = true;
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toastVisible.value = false; }, 2500);
    }
    ctx('showToast', showToast);
    view('toastMsg', toastMsg);
    view('toastType', toastType);
    view('toastVisible', toastVisible);

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
    let confirmSuppressWatch = false;

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
      confirmSuppressWatch = true;
      confirmModal.show = false;
      if (top) top.resolve(res);
      confirmSuppressWatch = false;
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

    // Resolve any confirm closed externally (backdrop / X) as "false".
    watch(() => confirmModal.show, (show) => {
      if (confirmSuppressWatch) return;
      if (!show && confirmQueue.length) closeConfirm(false);
    });

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
            active: spec.active,
            interval: spec.interval,
            load: spec.load,
            timer: null,
        });
    }

    function syncPolls() {
        if (!store.loggedIn) { stopAllPolls(); return; }
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
      // KB dirty-form guard (late-bound — vn-kb registers kbFormDirty via ctx)
      const kbFormDirty = shared.kbFormDirty;
      if (page.value === 'kb' && kbFormDirty && kbFormDirty.value) {
        if (!await showConfirm({
          title: '未保存的更改',
          message: 'KB 表单有未保存的更改，确定离开？',
          type: 'warning',
        })) return;
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

    // ---- Logout hooks ----
    // Modules register a callback here so that logging out can wipe their
    // per-session data (otherwise a re-login as a different account flashes
    // the previous session's records). doLogout() fires every hook.
    const logoutHooks = [];
    function onLogout(cb) { if (typeof cb === 'function') logoutHooks.push(cb); }
    ctx('onLogout', onLogout);

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
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();