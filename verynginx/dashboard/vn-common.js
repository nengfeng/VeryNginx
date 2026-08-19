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
    let csrfBroken = false;

    // Strict IP literal validation (IPv4 0-255 per octet, IPv6 with optional /prefix).
    // Mirrors api/helpers.lua is_valid_ip semantics on the client side.
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
          if (!Number.isInteger(p) || p < 0 || p > 128) return false;
        }
        return true;
      }
      // IPv4 literal (optionally with /<prefix>)
      const body = allowPrefix ? s.split('/')[0] : s;
      const parts = body.split('.');
      if (parts.length !== 4) return false;
      for (const p of parts) {
        if (!/^\d+$/.test(p)) return false;
        const n = Number(p);
        if (n < 0 || n > 255) return false;
        if (p.length > 1 && p[0] === '0') return false; // no leading zeros
      }
      if (allowPrefix && s.includes('/')) {
        const p = Number(s.split('/')[1]);
        if (!Number.isInteger(p) || p < 0 || p > 32) return false;
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
      if (method !== 'GET') {
        if (csrfBroken) {
          try {
            const d = await fetch('/verynginx/csrf', { method: 'GET', credentials: 'same-origin' });
            if (d.ok) {
              const j = await d.json();
              csrfToken = j.csrf_token;
              csrfBroken = false;
            } else if (d.status === 401 || d.status === 403) {
              csrfToken = null;
              csrfBroken = false;
              store.loggedIn = false;
              store.user = null;
              throw new Error('session_expired');
            }
          } catch (e) {
            if (e.message === 'session_expired') throw e;
          }
        }
        if (csrfBroken) {
          throw new Error('CSRF 令牌刷新失败，请刷新页面后重试');
        }
        if (csrfToken) {
          opts.headers = opts.headers || {};
          opts.headers['X-CSRF-Token'] = csrfToken;
        }
      }
      const res = await fetch(path, opts);
      if (!res.ok) {
        if ((res.status === 401 || res.status === 403) && path !== '/verynginx/login') {
          csrfToken = null;
          store.loggedIn = false;
          store.user = null;
          throw new Error('session_expired');
        }
        const text = await res.text().catch(() => '');
        let msg;
        try { const j = JSON.parse(text); msg = j.message || j.err || text; } catch { msg = text || `HTTP ${res.status}`; }
        throw new Error(msg);
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
      resolve: null,
      reject: null
    });
    view('confirmModal', confirmModal);

    function showConfirm({ title, message, type = 'danger', requireInput = false, inputLabel = '', inputExpected = '' }) {
      return new Promise((resolve, reject) => {
        confirmModal.show = true;
        confirmModal.title = title;
        confirmModal.message = message;
        confirmModal.type = type;
        confirmModal.requireInput = requireInput;
        confirmModal.inputLabel = inputLabel;
        confirmModal.inputValue = '';
        confirmModal.inputExpected = inputExpected;
        confirmModal.resolve = resolve;
        confirmModal.reject = reject;
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
      confirmModal.show = false;
      confirmModal.resolve(true);
    }
    view('confirmModalOk', confirmModalOk);

    function confirmModalCancel() {
      confirmModal.show = false;
      confirmModal.resolve(false);
    }
    view('confirmModalCancel', confirmModalCancel);

    // Watch for modal close - always resolve the pending Promise
    watch(() => confirmModal.show, (show) => {
      if (!show && confirmModal.resolve) {
        confirmModal.resolve(false);
      }
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
    ctx('clearCsrf', () => { csrfToken = null; csrfBroken = false; });

    // ---- Polling registry ----
    // Central lifecycle for every auto-refresh poller. Each poller declares an
    // `active()` predicate; syncPolls() reconciles start/stop on navigation.
    // Pollers MUST register here instead of wiring ad-hoc per-page watches -
    // ad-hoc clear logic is how the status/overview/health timer leak crept in.
    const polls = new Map();

    function registerPoll(name, spec) {
        if (polls.has(name)) {
            console.error('[VeryNginx] duplicate poll registration: ' + name);
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

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();