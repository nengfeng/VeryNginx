// vn-common.js - Domain module for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    
    window.VN.modules['vncommon'] = function createvncommonModule(ctx) {
        const { expose } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;
        
    // Module-level store so api() can access it for session expiration handling
    let store = reactive({ loggedIn: false, user: null });
    
    // ---- API ----
    let csrfToken = null;

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
              if (typeof store !== 'undefined') {
                store.loggedIn = false;
                store.user = null;
              }
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
        if (res.status === 401 || res.status === 403) {
          csrfToken = null;
          if (typeof store !== 'undefined') {
            store.loggedIn = false;
            store.user = null;
          }
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

    // ===== SHARED UI UTILITIES (toast, confirm modal) =====
    
    // Toast state (module-level refs for reactivity)
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
    expose('showToast', showToast);
    expose('toastMsg', toastMsg);
    expose('toastType', toastType);
    expose('toastVisible', toastVisible);

    // Confirm modal state
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
    expose('confirmModal', confirmModal);

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
    expose('showConfirm', showConfirm);

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
    expose('confirmModalOk', confirmModalOk);

    function confirmModalCancel() {
      confirmModal.show = false;
      confirmModal.resolve(false);
    }
    expose('confirmModalCancel', confirmModalCancel);

    // Watch for modal close
    watch(() => confirmModal.show, (show) => {
      if (!show && confirmModal.resolve) {
        confirmModal.resolve(false);
      }
    });

    // Write back to ctx for subsequent modules
    ctx.showToast = showToast;
    ctx.showConfirm = showConfirm;
    ctx.confirmModal = confirmModal;
    ctx.confirmModalOk = confirmModalOk;
    ctx.confirmModalCancel = confirmModalCancel;
    ctx.toastMsg = toastMsg;
    ctx.toastType = toastType;
    ctx.toastVisible = toastVisible;

    // ===== CORE STATE DECLARATIONS (from setup() initial state) =====
    
    // Expose module-level store for template access
    expose('store', store);
    const page = ref('dashboard');
        expose('page', page);
    const dashTab = ref('overview');
        expose('dashTab', dashTab);
    const advTab = ref('fingerprints');
        expose('advTab', advTab);
    const loading = ref(false);
        expose('loading', loading);
    const loginUser = ref('');
        expose('loginUser', loginUser);
    const loginPass = ref('');
        expose('loginPass', loginPass);
    const loginError = ref('');
        expose('loginError', loginError);
    const status = ref({});
        expose('status', status);
    const connHistory = ref([]);
        expose('connHistory', connHistory);
    const cfg = ref({});
        expose('cfg', cfg);
    const healthData = ref({});
        expose('healthData', healthData);
    const overview = ref({});
        expose('overview', overview);
    const dictUsage = ref([]);
        expose('dictUsage', dictUsage);
    // Shared audit filter state (used by vn-waf.js and vn-advanced.js)
    const auditFilterUser = ref('');
        expose('auditFilterUser', auditFilterUser);
    const auditFilterAction = ref('');
        expose('auditFilterAction', auditFilterAction);
    const auditFilterSince = ref('');
        expose('auditFilterSince', auditFilterSince);
    const auditFilterUntil = ref('');
        expose('auditFilterUntil', auditFilterUntil);

    ctx.auditFilterUser = auditFilterUser;
    ctx.auditFilterAction = auditFilterAction;
    ctx.auditFilterSince = auditFilterSince;
    ctx.auditFilterUntil = auditFilterUntil;

     const cfgTab = ref('system');
         expose('cfgTab', cfgTab);
     const theme = ref(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
         expose('theme', theme);

     function toggleTheme() {
         expose('toggleTheme', toggleTheme);
       const newTheme = theme.value === 'dark' ? 'light' : 'dark';
       theme.value = newTheme;
       document.documentElement.setAttribute('data-theme', newTheme);
       try { localStorage.setItem('vn_theme', newTheme); } catch(e) {}
     }
    const rawJson = ref('');
        expose('rawJson', rawJson);
    const jsonError = ref('');
        expose('jsonError', jsonError);
    watch(rawJson, (val) => {
      jsonError.value = '';
      if (!val) return;
      try { JSON.parse(val); } catch (e) { jsonError.value = 'JSON: ' + e.message; }
    });
    const jsonSaving = ref(false);
        expose('jsonSaving', jsonSaving);
    const statsData = ref(null);
        expose('statsData', statsData);
    const statsType = ref('long');
        expose('statsType', statsType);
    const statsError = ref('');
        expose('statsError', statsError);
    const expandedUri = ref(null);
        expose('expandedUri', expandedUri);
    const editMatcherModal = reactive({ show: false, name: '', conditions: '' });
        expose('editMatcherModal', editMatcherModal);

    // expose core utilities
    expose('api', api);
    expose('isValidIpLiteral', isValidIpLiteral);
    expose('refreshCsrf', refreshCsrf);
    expose('refreshCsrfOnce', refreshCsrfOnce);
    expose('csrfToken', () => csrfToken); // getter for current token

    // Write back to ctx for subsequent modules
    ctx.api = api;
    ctx.store = store;
    ctx.isValidIpLiteral = isValidIpLiteral;
    ctx.refreshCsrf = refreshCsrf;
    ctx.refreshCsrfOnce = refreshCsrfOnce;
    ctx.csrfToken = () => csrfToken;

        
        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();