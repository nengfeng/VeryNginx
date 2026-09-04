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
        // IPv4-mapped IPv6 literal (::ffff:a.b.c.d): validate embedded v4.
        const mapped = s.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        if (mapped) {
          ip = mapped[1]; // fall through to the IPv4 path below
        } else {
          // IPv6 literal (optionally /<prefix> for whitelist use). NOTE: v6
          // CIDR is rejected — server-side matching only does v4 math + exact
          // string equality, so an accepted v6 CIDR would be a silent dead entry.
          const body = allowPrefix ? s.split('/')[0] : s;
          if (!/^[0-9a-fA-F:]+$/.test(body) || !body.includes(':')) return false;
          if (allowPrefix && s.includes('/')) return false;
          return true;
        }
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

      // 429 = API rate limited (api/init.lua middleware, e.g. hammering
      // POST /config). Translate to one actionable line — the raw body tells
      // the operator nothing about what to do differently.
      if (res.status === 429) {
        throw new Error('操作过于频繁，请稍候重试');
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

    function showToast(msg, type, opts) {
      opts = opts || {};
      const t = type || 'info';
      // Dedup consecutive identical messages — a poller erroring every 3s
      // must not fill the sticky stack with copies of one failure.
      const last = toasts.value[toasts.value.length - 1];
      if (!opts.actionLabel && last && last.type === t && last.msg === String(msg)) return;
      const item = {
        id: ++toastSeq, msg: String(msg), type: t, timer: null,
        actionLabel: String(opts.actionLabel || ''),
        onAction: typeof opts.onAction === 'function' ? opts.onAction : null,
      };
      toasts.value.push(item);
      while (toasts.value.length > TOAST_MAX) {
        const dropped = toasts.value.shift();
        if (dropped.timer) clearTimeout(dropped.timer);
      }
      let dur = TOAST_DURATION[t] === undefined ? 3000 : TOAST_DURATION[t];
      if (opts.duration != null) dur = opts.duration;
      if (dur > 0) item.timer = setTimeout(() => dismissToast(item.id), dur);
    }
    ctx('showToast', showToast);

    // Undoable-action toast: shows a success toast with a 10s "撤销" button
    // that runs the reverse API. Replaces the per-module kbUndoToast pattern.
    function showUndoToast(msg, undoFn) {
      showToast(msg, 'success', {
        actionLabel: '撤销',
        duration: 10000,
        onAction: async () => {
          try { await undoFn(); }
          catch (e) { showToast('撤销失败: ' + e.message, 'error'); }
        },
      });
    }
    // showUndoToast is a module-level utility, not a template binding.
    ctx('showUndoToast', showUndoToast);

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
    // Top-level group navigation: 'dashboard' | 'protect' | 'system' | 'config' | 'advanced' | 'about'
    const groupPage = ref('dashboard');
    view('groupPage', groupPage);
    const dashTab = ref('overview');
    view('dashTab', dashTab);
    const advTab = ref('fingerprints');
    view('advTab', advTab);
    const cfgTab = ref('system');
    view('cfgTab', cfgTab);
    const theme = ref(document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light');
    view('theme', theme);
    const mobileNavOpen = ref(false);
    view('mobileNavOpen', mobileNavOpen);

    // ---- First-time intro tour ----
    // 引导步骤配置：导航目标 + 描述文案（先定义，view() 注册后才能引用）
    const INTRO_STEPS = [
      {
        page: 'dashboard',
        title: '仪表盘',
        body: '这是你的首页，显示连接数、请求速率、上游健康、WAF 命中和共享字典使用率。数字变红或变黄时说明需要关注。',
      },
      {
        page: 'waf',
        title: '看到攻击了？去「防护」→ WAF',
        body: '点击顶部「防护」→「WAF」→「攻击」→「命中」，这里列出所有被拦截的请求。点任意一行可展开完整详情（IP、URI、TLS 指纹、请求头），用于事后分析和调优规则。',
      },
      {
        page: 'frequency',
        title: '频率限制 — 防 CC / 暴力破解',
        body: '防护 → 频率限制。按模板一键套用登录防爆破、API 限流等场景，或用「+ 手动新建」自定义规则。规则生效后会立即限制超限请求。',
      },
      {
        page: 'kb',
        title: '内核封禁 — 系统级自动拦截',
        body: '系统 → 内核封禁。将屡教不改的恶意 IP 直接封在系统内核层。注意观察/执行模式的区别：观察只记日志，执行才会真正写入封禁表。',
      },
    ];

    const introStep = ref(0); // 0=未开始, 1-4=步骤, 5=已完成
    const introShow = ref(false);
    view('INTRO_STEPS', INTRO_STEPS);
    view('introStep', introStep);
    view('introShow', introShow);

    function startIntro() {
      introStep.value = 1;
      introShow.value = true;
    }
    function completeIntro() {
      try { localStorage.setItem('vn_seen_intro', '1'); } catch(e) {}
      introShow.value = false;
      introStep.value = 0;
    }
    function replayIntro() {
      try { localStorage.removeItem('vn_seen_intro'); } catch(e) {}
      startIntro();
    }
    view('completeIntro', completeIntro);
    view('replayIntro', replayIntro);
    view('introNext', introNext);
    view('introBack', introBack);

    function introNext() {
      const s = introStep.value;
      if (s >= INTRO_STEPS.length) { completeIntro(); return; }
      const step = INTRO_STEPS[s];
      introStep.value = s + 1;
      // Navigate to the target page/tab; wait for data load
      if (shared.navigateTo) shared.navigateTo(step.page);
    }
    function introBack() {
      const s = introStep.value;
      if (s <= 1) { completeIntro(); return; }
      const step = INTRO_STEPS[s - 2];
      introStep.value = s - 1;
      if (shared.navigateTo) shared.navigateTo(step.page);
    }

    // 登录成功后若为首次访问则弹出引导
    let _introTriggered = false;
    watch(() => store.loggedIn, (v) => {
      if (v) {
        // Start nowTick ticker so "最后更新" label stays fresh.
        _startNowTick();
        // Fire intro tour on first login only.
        if (!_introTriggered) {
          _introTriggered = true;
          try {
            if (!localStorage.getItem('vn_seen_intro')) startIntro();
          } catch(e) {}
        }
      } else {
        _stopNowTick();
      }
    });

    // ---- Command palette (Ctrl+K) + keyboard shortcuts help (?) ----
    const cmdPaletteOpen = ref(false);
    const cmdQuery = ref('');
    const kbShortcutsOpen = ref(false);
    view('cmdPaletteOpen', cmdPaletteOpen);
    view('cmdQuery', cmdQuery);
    view('kbShortcutsOpen', kbShortcutsOpen);

    // Commands available in the palette; each has a label, optional shortcut,
    // and either a page target or an action callback.
    const CMD_ACTIONS = [
      { label: '仪表盘', shortcut: '1', action: () => { navigateTo('dashboard'); cmdPaletteOpen.value = false; } },
      { label: '防护 · WAF', shortcut: '2', action: () => { navigateTo('waf'); cmdPaletteOpen.value = false; } },
      { label: '防护 · 频率限制', shortcut: null, action: () => { navigateTo('frequency'); cmdPaletteOpen.value = false; } },
      { label: '防护 · IP 声誉', shortcut: null, action: () => { navigateTo('reputation'); cmdPaletteOpen.value = false; } },
      { label: '系统 · 内核封禁', shortcut: '3', action: () => { navigateTo('kb'); cmdPaletteOpen.value = false; } },
      { label: '系统 · GeoIP', shortcut: null, action: () => { navigateTo('geoip'); cmdPaletteOpen.value = false; } },
      { label: '配置管理', shortcut: '4', action: () => { navigateTo('config'); cmdPaletteOpen.value = false; } },
      { label: '高级 · TLS 指纹', shortcut: '5', action: async () => { cmdPaletteOpen.value = false; if (await navigateTo('advanced')) advTab.value = 'fingerprints'; } },
      { label: '高级 · 审计日志', shortcut: null, action: async () => { cmdPaletteOpen.value = false; if (await navigateTo('advanced')) advTab.value = 'audit'; } },
      { label: '关于', shortcut: '6', action: () => { navigateTo('about'); cmdPaletteOpen.value = false; } },
      { label: '切换深色/浅色模式', shortcut: '⌘D', action: () => { toggleTheme(); cmdPaletteOpen.value = false; } },
    ];
    ctx('CMD_ACTIONS', CMD_ACTIONS);

    // Filtered commands based on query
    const cmdFiltered = computed(() => {
      const q = cmdQuery.value.trim().toLowerCase();
      if (!q) return CMD_ACTIONS;
      return CMD_ACTIONS.filter(a => a.label.toLowerCase().includes(q));
    });
    view('cmdFiltered', cmdFiltered);

    function openCmdPalette() {
      cmdQuery.value = '';
      cmdPaletteOpen.value = true;
      Vue.nextTick(() => {
        const input = document.querySelector('#cmd-palette-input');
        if (input) input.focus();
      });
    }
    function closeCmdPalette() { cmdPaletteOpen.value = false; cmdQuery.value = ''; }
    ctx('openCmdPalette', openCmdPalette);
    view('closeCmdPalette', closeCmdPalette);
    view('cmdSelect', (action) => { action(); cmdPaletteOpen.value = false; });
    const cmdIdx = ref(0);
    view('cmdIdx', cmdIdx);
    // Watch cmdQuery: reset idx so filtered results always start at top.
    watch(cmdQuery, () => { cmdIdx.value = 0; });

    // Cmd palette keyboard nav: ↑↓ arrows, Enter, Escape
    window.addEventListener('keydown', (e) => {
      if (!cmdPaletteOpen.value) return;
      const items = document.querySelectorAll('.cmd-item');
      if (e.key === 'ArrowDown') { e.preventDefault(); cmdIdx.value = Math.min(cmdIdx.value + 1, items.length - 1); items[cmdIdx.value]?.scrollIntoView({ block: 'nearest' }); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); cmdIdx.value = Math.max(cmdIdx.value - 1, 0); items[cmdIdx.value]?.scrollIntoView({ block: 'nearest' }); }
      else if (e.key === 'Enter') { e.preventDefault(); const action = cmdFiltered.value[cmdIdx.value]?.action; if (action) action(); cmdPaletteOpen.value = false; }
    });

    // Keyboard shortcuts reference list for the help modal
    const KB_SHORTCUTS = [
      ['⌘K', '打开命令面板'],
      ['?', '显示快捷键帮助'],
      ['Esc', '关闭弹窗/面板'],
      ['1–6', '跳转到主导航项（仪表盘/WAF/内核封禁/配置/高级/关于）'],
      ['⌘D', '切换深色/浅色模式'],
      ['←→', '在可排序表头间移动焦点'],
      ['Enter / Space', '对聚焦的列切换排序方向'],
    ];
    view('KB_SHORTCUTS', KB_SHORTCUTS);

    // Global keydown: Ctrl+K open palette, ? show shortcuts, Esc close either.
    // This runs BEFORE the modal Tab-trap handler so palette/shortcuts can
    // intercept even when a modal is open.
    window.addEventListener('keydown', (e) => {
      // Ctrl/Cmd+K → command palette
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        cmdPaletteOpen.value = !cmdPaletteOpen.value;
        if (cmdPaletteOpen.value) cmdQuery.value = '';
        return;
      }
      // ? → shortcuts help (only when not typing in an input)
      if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        const tag = document.activeElement && document.activeElement.tagName;
        if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
          e.preventDefault();
          kbShortcutsOpen.value = !kbShortcutsOpen.value;
        }
      }
      // Ctrl/Cmd+D → toggle theme (guard against typing in input fields).
      // ⚠️ Do NOT use Ctrl/Cmd+1-9 here: browsers intercept those at the UI
      // layer (tab-switching) before JavaScript ever sees them, so
      // preventDefault() is ineffective and the handler never fires.
      if ((e.ctrlKey || e.metaKey) && e.key === 'd' && !e.shiftKey) {
        const tag = document.activeElement && document.activeElement.tagName;
        if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
          e.preventDefault();
          toggleTheme();
        }
      }
      // Plain 1-6 → jump to top-level nav (no modifier — matches GitHub/Linear/
      // Notion convention and avoids all browser-reserved key combos).
      if (!e.ctrlKey && !e.metaKey && !e.shiftKey && !cmdPaletteOpen.value && !kbShortcutsOpen.value && !confirmModal.show) {
        const tag = document.activeElement && document.activeElement.tagName;
        if (tag !== 'INPUT' && tag !== 'TEXTAREA' && tag !== 'SELECT') {
          const num = parseInt(e.key, 10);
          if (num >= 1 && num <= 6) {
            e.preventDefault();
            const targets = ['dashboard','waf','kb','config','advanced','about'];
            const t = targets[num - 1];
            if (t) { navigateTo(t); mobileNavOpen.value = false; }
          }
        }
      }
    });
    // Close palette/shortcuts on Escape (separate from modal Escape trap).
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        if (cmdPaletteOpen.value) { closeCmdPalette(); e.preventDefault(); }
        else if (kbShortcutsOpen.value) { kbShortcutsOpen.value = false; e.preventDefault(); }
      }
    });

    // view('theme', theme); is BELOW — keep intro setup here, defer onLogout
    // registration until logoutHooks exists (see the block after line ~680).

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
    // Login field helpers: password visibility toggle + Caps Lock detection
    // (the two most common causes of a mistyped admin password).
    const loginPassVisible = ref(false);
    view('loginPassVisible', loginPassVisible);
    const loginCapsLock = ref(false);
    view('loginCapsLock', loginCapsLock);
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
    view('isValidIpLiteral', isValidIpLiteral);
    ctx('refreshCsrf', refreshCsrf);
    ctx('refreshCsrfOnce', refreshCsrfOnce);
    ctx('csrfToken', () => csrfToken); // getter for current token
    ctx('clearCsrf', () => { csrfToken = null; });

    // Audit ring buffer size — must match core/audit.lua RING_SIZE (1000).
    // Used by vn-advanced.js and vn-kb.js for the audit API limit.
    const AUDIT_LIMIT = 1000;
    ctx('AUDIT_LIMIT', AUDIT_LIMIT);

    // ---- Polling registry ----
    // Refresh transparency: pause switch + per-poll last-run timestamps. The
    // badge computes "最后更新 N 秒前" from the newest stamp; a 1s ticker
    // re-renders the label without touching any data ref.
    const autoRefreshPaused = ref(false);
    view('autoRefreshPaused', autoRefreshPaused);
    const lastUpdated = {};
    const nowTick = ref(Date.now());
    // nowTick drives the "最后更新 X 秒前" label. Run only while logged in so
    // the interval is killed on logout (consistent with registerPoll semantics).
    let _nowTickTimer = null;
    function _startNowTick() { if (_nowTickTimer) return; _nowTickTimer = setInterval(() => { nowTick.value = Date.now(); }, 1000); }
    function _stopNowTick() { if (!_nowTickTimer) return; clearInterval(_nowTickTimer); _nowTickTimer = null; }
    const lastRefreshLabel = computed(() => {
        let newest = 0;
        for (const t of Object.values(lastUpdated)) { if (t > newest) newest = t; }
        if (!newest || !store.loggedIn) return '';
        const sec = Math.max(0, Math.floor((nowTick.value - newest) / 1000));
        return sec < 5 ? '刚刚更新' : '最后更新 ' + sec + ' 秒前';
    });
    view('lastRefreshLabel', lastRefreshLabel);
    // Pages where an active poller exists — badge only shown when the current
    // page is one of these. Without this guard, the badge would display a
    // stale "last updated N seconds ago" on pages (waf, kb, advanced, etc.)
    // that have no live auto-refresh at all.
    const pollActivePages = ref([]);
    view('pollActivePages', pollActivePages);
    function refreshPollActivePages() {
        // Read declared pages from poll specs for active timers.
        const result = new Set();
        for (const [, p] of polls) {
            if (p.timer !== null) {
                for (const pg of p.pages) result.add(pg);
            }
        }
        pollActivePages.value = [...result];
    }
    // Re-evaluate on navigation so the badge reflects the current page
    // regardless of watch-registration order (syncPolls may run before or
    // after this watcher; calling refreshPollActivePages at the end of
    // syncPolls is the canonical trigger point).
    watch([page, dashTab, cfgTab], refreshPollActivePages);
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
            // Declared pages this poller covers. Used by refreshPollActivePages
            // so the badge knows which page to show on without depending on
            // timer state or hard-coded name checks.
            pages: spec.pages || [],
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
        refreshPollActivePages();
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
    ctx('refreshPollActivePages', refreshPollActivePages);

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
        })) return false;
        discardUnsaved();
      }
      page.value = newPage;
      // Sync top-level group based on target page
      if (newPage === 'dashboard') groupPage.value = 'dashboard';
      else if (['waf', 'frequency', 'reputation'].includes(newPage)) groupPage.value = 'protect';
      else if (['geoip', 'kb'].includes(newPage)) groupPage.value = 'system';
      else if (newPage === 'config') groupPage.value = 'config';
      else if (newPage === 'advanced') groupPage.value = 'advanced';
      else if (newPage === 'about') groupPage.value = 'about';
      // Per-page data loading
      if (newPage === 'waf') { if (shared.loadWafData) await shared.loadWafData(); }
      else if (newPage === 'frequency') { if (shared.loadFrequencyData) await shared.loadFrequencyData(); }
      else if (newPage === 'reputation') { if (shared.loadRepData) await shared.loadRepData(); }
      else if (newPage === 'geoip') { if (shared.loadGeoIP) await shared.loadGeoIP(); if (shared.loadGeoIPStatus) await shared.loadGeoIPStatus(); }
      else if (newPage === 'kb') { if (shared.loadKbData) await shared.loadKbData(); }
      return true;
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
    ctx('discardUnsaved', discardUnsaved);

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
    // Defer intro logout hook registration until logoutHooks is initialized.
    if (typeof introStep !== 'undefined') {
      onLogout(() => {
        _introTriggered = false;
        try { localStorage.removeItem('vn_seen_intro'); } catch(e) {}
        introShow.value = false;
        introStep.value = 0;
      });
    }
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
    // Keyboard: columns are focusable (tabindex=0 via CSS class), ArrowRight
    // / ArrowLeft walk the column list, Enter/Toggle sort by that column.
    // Binding is lazy: the global keydown handler populates sortKeys on first
    // interaction with a given table, so it works regardless of when the table
    // enters the DOM (v-if pages, lazy-loaded modules, etc.).
    function createTableTools(sourceRef) {
      const state = reactive({ sortKey: '', sortDir: 1, filter: '' });
      const rows = computed(() => {
        let list = (sourceRef && sourceRef.value) || [];
        if (Array.isArray(list)) list = list.filter(r => r && typeof r === 'object');
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
      const sortKeys = [];
      // MUST be reactive(): template ref-unwrapping is SHALLOW — a computed
      // inside a PLAIN returned object stays a ref, so v-for="r in t.rows"
      // iterates the ref instance itself and any r.id access throws,
      // white-screening the subtree (proxyRefs unwraps only setup() top-level
      // or reactive() members). reactive() unwraps `rows` to the array.
      // Consequence for script code: read `.rows` DIRECTLY (no .value).
      return reactive({ state, rows, sortBy, sortKeys });
    }
    ctx('createTableTools', createTableTools);
    // Global delegated listener for sortable-table keyboard interaction.
    // Lazy-binds: on first keystroke against a table, scans its <th> elements
    // to populate sortKeys. This avoids relying on any lifecycle hook and
    // works correctly even when tables are created after module load (v-if
    // page switches, dynamic content, etc.).
    if (typeof document !== 'undefined') {
      document.addEventListener('keydown', (e) => {
        if (!e.target || !e.target.closest) return;
        const th = e.target.closest('th.sortable[tabindex="0"]');
        if (!th) return;
        const col = th.getAttribute('data-sort-col');
        if (!col) return;
        const table = th.closest('table');
        if (!table) return;
        let tools = table.__vnTools;
        // Lazy-bind: first time this table sees a keyboard event, populate
        // sortKeys from the DOM so Arrow-key travel works immediately.
        if (!tools) {
          tools = { sortKeys: [] };
          for (const t of table.querySelectorAll('th.sortable[tabindex="0"]')) {
            const k = t.getAttribute('data-sort-col');
            if (k && !tools.sortKeys.includes(k)) tools.sortKeys.push(k);
          }
          table.__vnTools = tools;
        }
        const keys = tools.sortKeys || [];
        const idx = keys.indexOf(col);
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          // Click-compatible sort toggle: find the matching tools state from
          // the factory; fall back to a no-op if this is a late-bound stub
          // (only the lazy stub path, since real factory tools expose sortBy).
          if (typeof tools.sortBy === 'function') tools.sortBy(col);
        } else if (e.key === 'ArrowRight') {
          e.preventDefault();
          const next = keys[(idx + 1) % Math.max(keys.length, 1)];
          if (next) document.querySelector(`th[data-sort-col="${CSS.escape(next)}"]`)?.focus();
        } else if (e.key === 'ArrowLeft') {
          e.preventDefault();
          const prev = keys[(idx - 1 + Math.max(keys.length, 1)) % Math.max(keys.length, 1)];
          if (prev) document.querySelector(`th[data-sort-col="${CSS.escape(prev)}"]`)?.focus();
        }
      });
    }

    // ---- Safe list coercion ----
    // API arrays must never hand null/undefined ITEMS to a v-for: a single
    // corrupt entry crashes the whole render ("Cannot read properties of
    // undefined (reading 'id')"). Use for every list assigned from a response.
    function asList(v) {
      return (Array.isArray(v) ? v : []).filter(r => r != null);
    }
    ctx('asList', asList);

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
        refreshPollActivePages();
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
      // Stop the nowTick ticker so it doesn't keep firing after logout.
      _stopNowTick();
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