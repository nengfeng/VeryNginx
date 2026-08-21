// vn-dashboard.js - Dashboard module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-common.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vndashboard'] = function createvndashboardModule(shared) {
        const { ctx, view, api, store, page, dashTab, advTab, cfgTab, loading, loginUser, loginPass, loginError, sessionExpiredNotice, status, connHistory, cfg, healthData, overview, dictUsage, rawJson, statsData, statsType, statsError, versionInfo, topPaths, refreshCsrf, showToast, registerPoll, syncPolls, stopAllPolls } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Version ----
    async function loadVersion() {
      try {
        const d = await api('GET', '/verynginx/version');
        if (d.ret === 'success') versionInfo.value = d.data;
      } catch (e) {
        console.warn('Version load failed:', e.message);
      }
    }


    // ---- Overview ----
    function parsePrometheus(text) {
      const result = {};
      const lines = text.split('\n');
      for (const line of lines) {
        if (line.startsWith('#') || !line.trim()) continue;
        // Match: name{labels} value
        const m = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{.*?\})?\s+([0-9.e+\-]+)/);
        if (!m) continue;
        const name = m[1];
        const labelStr = m[2] || '';
        const value = parseFloat(m[3]);
        // Parse labels
        const labels = {};
        if (labelStr) {
          const inner = labelStr.slice(1, -1);
          for (const pair of inner.split(',')) {
            const eq = pair.indexOf('=');
            if (eq < 0) continue;
            const lk = pair.slice(0, eq).trim();
            const lv = pair.slice(eq + 1).replace(/^"|"$/g, '');
            labels[lk] = lv;
          }
        }
        if (!result[name]) result[name] = {};
        const lk = JSON.stringify(labels);
        result[name][lk] = value;
      }
      return result;
    }

    async function loadOverview() {
      const tok = gOverview.mark();
      const o = { conn_active: 0, req_rate: 0, up_healthy: 0, up_total: 0, waf_hits: 0, dicts: [], top_uris: [], plugin_errors: [] };
      try {
        // Status: connection counts
        const s = await api('GET', '/verynginx/status');
        o.conn_active = s.connections_active || 0;

        // Health: upstream node status
        const h = await api('GET', '/verynginx/upstreams/health');
        if (h.ret === 'success') {
          for (const [name, nodes] of Object.entries(h.data || {})) {
            for (const n of nodes) {
              o.up_total++;
              if (n.healthy && !n.circuit_open) o.up_healthy++;
            }
          }
        }

        // Metrics: shared dict usage, plugin errors, request total
        const m = await api('GET', '/verynginx/metrics', null, { text: true });
        const parsed = parsePrometheus(typeof m === 'string' ? m : '');

        for (const [key, vals] of Object.entries(parsed)) {
          if (key.startsWith('shared_dict_usage_pct')) {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              if (lb.dict) o.dicts.push({ name: lb.dict, pct: val, used: 0, cap: 0 });
            }
          } else if (key.startsWith('shared_dict_usage_bytes')) {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              let d = (o.dicts || []).find(x => x.name === lb.dict);
              if (!d) { o.dicts.push({ name: lb.dict, pct: 0, used: 0, cap: 0 }); d = o.dicts[o.dicts.length - 1]; }
              d.used = val; if (!d.cap) { const p = parsed['shared_dict_capacity_bytes']; if (p) for (const [lk, v] of Object.entries(p)) { const l = JSON.parse(lk); if (l.dict === lb.dict) d.cap = v; } }
            }
          } else if (key === 'vn_plugin_errors_total') {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              o.plugin_errors.push({ plugin: lb.plugin || '?', phase: lb.phase || '?', count: val });
            }
          } else if (key === 'plugin_duration_seconds_count') {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              o._plugin_dur_count = o._plugin_dur_count || {};
              const k = (lb.plugin || '?') + '|' + (lb.phase || '?');
              o._plugin_dur_count[k] = val;
            }
          } else if (key === 'plugin_duration_seconds_sum') {
            for (const [labels, val] of Object.entries(vals)) {
              const lb = JSON.parse(labels);
              o._plugin_dur_sum = o._plugin_dur_sum || {};
              const k = (lb.plugin || '?') + '|' + (lb.phase || '?');
              o._plugin_dur_sum[k] = val;
            }
          } else if (key === 'vn_requests_total') {
            o.req_rate = Math.round(Object.values(vals)[0] || 0);
          }
        }

        // Summary: top URIs
        const sum = await api('GET', '/verynginx/summary?type=short');
        if (sum.ret === 'success' && sum.data) {
          const entries = Object.entries(sum.data).map(([uri, v]) => ({
            uri,
            count: v.count || 0,
            bytes: v.bytes || 0,
            success_rate: v.count ? ((v.success || 0) / v.count * 100) : 100
          }));
          entries.sort((a, b) => b.count - a.count);
          o.top_uris = entries.slice(0, 10);
        }

        // WAF hits summary
        try {
          const w = await api('GET', '/verynginx/waf/stats');
          if (w.ret === 'success' && w.data) {
            o.waf_hits = Object.values(w.data).reduce((s, r) => s + (r.hits || 0), 0);
          }
        } catch (e) {
          console.warn('Overview WAF stats failed:', e.message);
        }

        // Reputation summary
        try {
          const r = await api('GET', '/verynginx/reputation/stats');
          if (r.ret === 'success' && r.data) {
            o.flagged = r.data.flagged || 0;
          }
        } catch (e) {
          console.warn('Overview reputation stats failed:', e.message);
        }
      } catch (e) {
        console.warn('Overview load error:', e.message);
      }
      // Merge plugin errors with duration into plugin_perf
      const perfMap = {};
      for (const e of (o.plugin_errors || [])) {
        const k = e.plugin + '|' + e.phase;
        perfMap[k] = { plugin: e.plugin, phase: e.phase, errors: e.count, avg_ms: 0, count: 0 };
      }
      for (const [k, cnt] of Object.entries(o._plugin_dur_count || {})) {
        if (!perfMap[k]) perfMap[k] = { plugin: k.split('|')[0], phase: k.split('|')[1], errors: 0, avg_ms: 0, count: 0 };
        perfMap[k].count = cnt;
      }
      for (const [k, sum] of Object.entries(o._plugin_dur_sum || {})) {
        if (perfMap[k]) {
          perfMap[k].avg_ms = perfMap[k].count > 0 ? (sum / perfMap[k].count) * 1000 : 0;
        }
      }
      o.plugin_perf = Object.values(perfMap).sort((a, b) => b.avg_ms - a.avg_ms);
      delete o.plugin_errors;
      delete o._plugin_dur_count;
      delete o._plugin_dur_sum;
      o.dicts = (o.dicts || []).sort((a, b) => b.pct - a.pct).slice(0, 6);
      if (!gOverview.isCurrent(tok)) return;
      overview.value = o;
    }


    // ---- Auto-refresh polling ----
    // Every poller lives in the central registry (vn-common) and declares an
    // `active()` predicate. A single [page, dashTab, cfgTab] watcher reconciles
    // all pollers, so navigation can never leak an interval.
    registerPoll('status', {
        active: () => page.value === 'dashboard' && dashTab.value === 'status',
        interval: 3000,
        load: loadStatus,
    });
    registerPoll('overview', {
        active: () => page.value === 'dashboard' && dashTab.value === 'overview',
        interval: 5000,
        load: loadOverview,
    });
    registerPoll('health', {
        active: () => page.value === 'config' && cfgTab.value === 'upstreams',
        interval: 10000,
        load: loadHealth,
    });

    // Single reconciler: page/dashTab/cfgTab navigation starts/stops pollers.
    watch([page, dashTab, cfgTab], syncPolls);

    // Stats tab: load on entry (tab click OR returning to the page), so the
    // stats view is never stale after navigating away and back.
    watch([page, dashTab], ([p, d]) => {
      if (p === 'dashboard' && d === 'stats' && store.loggedIn) loadStats();
    });

    // Advanced tab load (fingerprints / audit) - late-bound via shared
    watch([page, advTab], ([p, d]) => {
      if (p === 'advanced') {
        if (d === 'fingerprints') { if (shared.loadFingerprints) shared.loadFingerprints(); }
        else { if (shared.loadAudit) shared.loadAudit(); }
      }
    });

    // Config tab: dict usage on system tab. Combined page+cfgTab watch so the
    // first entry into 配置→系统 loads usage without a manual button click
    // (a cfgTab-only watch never fires when cfgTab is already 'system').
    watch([page, cfgTab], ([p, tab]) => {
      if (p === 'config' && tab === 'system' && store.loggedIn) loadDictUsage();
    });

    // Stop all polling and wipe per-session module data whenever the session
    // ends. Centralizing here covers BOTH end paths: explicit doLogout() and
    // server-side expiry (api() flips store.loggedIn on a failed 401 self-heal)
    // — the latter never goes through doLogout.
    watch(() => store.loggedIn, (loggedIn) => {
      if (!loggedIn) {
        stopAllPolls();
        if (shared.runLogoutHooks) shared.runLogoutHooks();
      }
    });

    // Kick off on first mount: restore an existing session cookie so a page
    // reload doesn't force re-login.
    Vue.nextTick(async () => {
      const d = await api('GET', '/verynginx/session').catch(() => null);
      if (d && d.ret === 'success') {
        store.loggedIn = true;
        store.user = d.user;
        await refreshCsrf();
        loadVersion();
        loadConfig();
        syncPolls();
        // Hash routing may have restored a non-default view before mount; its
        // page-change watchers never fired, so run the per-page loaders once.
        if (shared.navigateTo) await shared.navigateTo(shared.page.value);
      }
    });


    // ---- Stats ----
    const gStats = shared.createStaleGuard();
    const gOverview = shared.createStaleGuard();
    async function loadStats() {
      const tok = gStats.mark();
      statsError.value = '';
      try {
        statsData.value = await api('GET', `/verynginx/summary?type=${statsType.value}`);
        if (!gStats.isCurrent(tok)) return;
      } catch (e) {
        if (gStats.isCurrent(tok)) statsError.value = e.message;
        return;
      }
      loadTopPaths();
    }


    // ---- Helpers ----
    function formatTime(t) {
      if (!t) return '-';
      return new Date(t * 1000).toLocaleString();
    }

    function formatBytes(b) {
      if (b == null) return '-';
      if (b < 1024) return b.toFixed(0) + ' B';
      if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
      return (b / 1048576).toFixed(1) + ' MB';
    }

    function calcSuccess(v) {
      let ok = 0, total = 0;
      for (const code in v.status || {}) {
        const c = v.status[code];
        total += c;
        if (parseInt(code) < 400) ok += c;
      }
      return total ? ((ok / total) * 100).toFixed(1) : '0.0';
    }

    function successClass(v) {
      // Accepts either a stats object (with .status) or an already-computed
      // numeric success rate (e.g. overview.top_uris[].success_rate).
      const p = (typeof v === 'number') ? v : parseFloat(calcSuccess(v));
      if (p >= 99) return 'tag-ok';
      if (p >= 90) return 'tag-warn';
      return 'tag-err';
    }

    function summarizeRule(r) {
      const parts = [];
      if (r.to_uri) parts.push('→ ' + r.to_uri);
      if (r.upstream) parts.push('→ ' + r.upstream);
      if (r.code) parts.push('HTTP ' + r.code);
      if (r.scheme) parts.push(r.scheme);
      if (r.rate) parts.push(r.rate);
      return parts.join(', ') || '-';
    }

    function actionClass(a) {
      if (a === 'block' || a === 'filter') return 'tag-err';
      if (a === 'accept' || a === 'proxy' || a === 'static') return 'tag-ok';
      return 'tag-warn';
    }


    // ---- Load ----
    async function loadStatus() {
      try {
        const s = await api('GET', '/verynginx/status');
        status.value = s;
        // Push to connection history ring buffer (max 60 points, 3s each = 3 min)
        const h = connHistory.value;
        h.push(s.connections_active || 0);
        if (h.length > 60) h.shift();
        connHistory.value = [...h];
      } catch (e) {
        console.warn('Status refresh failed:', e.message);
      }
    }

    async function loadConfig() {
      try {
        const d = await api('GET', '/verynginx/config');
        cfg.value = d;
        rawJson.value = JSON.stringify(d, null, 2);
        // Textarea re-synced from saved state — any dirty marker is stale.
        if (shared.jsonDirty) shared.jsonDirty.value = false;
      } catch (e) {
        showToast('配置加载失败: ' + e.message, 'error');
      }
    }

    async function refreshConfig(silent) {
      await Promise.allSettled([loadConfig(), loadHealth()]);
      if (cfgTab.value === 'plugins') { if (shared.loadPlugins) await shared.loadPlugins(); }
      if (!silent) showToast('配置已刷新', 'success');
    }

    async function loadHealth() {
      try {
        const d = await api('GET', '/verynginx/upstreams/health');
        if (d.ret === 'success') healthData.value = d.data || {};
      } catch (e) {
        console.warn('Upstream health check failed:', e.message);
      }
    }


    // ---- Dict Usage ----
    async function loadDictUsage() {
      try {
        const text = await api('GET', '/verynginx/metrics', null, { text: true });
        const parsed = parsePrometheus(typeof text === 'string' ? text : '');
        const dicts = [];
        const pctMap = {}, usedMap = {}, capMap = {};
        for (const [key, vals] of Object.entries(parsed)) {
          for (const [labels, val] of Object.entries(vals)) {
            const lb = JSON.parse(labels);
            if (key.startsWith('shared_dict_usage_pct')) {
              pctMap[lb.dict] = val;
            } else if (key.startsWith('shared_dict_usage_bytes')) {
              usedMap[lb.dict] = val;
            } else if (key.startsWith('shared_dict_capacity_bytes')) {
              capMap[lb.dict] = val;
            }
          }
        }
        for (const name of Object.keys(pctMap).sort()) {
          dicts.push({
            name,
            pct: pctMap[name] || 0,
            used: usedMap[name] || 0,
            cap: capMap[name] || 0
          });
        }
        dictUsage.value = dicts;
      } catch (e) {
        console.warn('Dict usage load failed:', e.message);
      }
    }


    // ---- Top Paths ----
    async function loadTopPaths() {
      try {
        const d = await api('GET', '/verynginx/stats/top-paths?limit=20');
        if (d.ret === 'success') {
          topPaths.value = d.data || [];
        }
      } catch (e) {
        console.warn('Top paths load failed:', e.message);
      }
    }


    // ---- Login ----
    // Server returns bare failure codes (api/auth.lua); map them to actionable
    // Chinese text instead of showing raw identifiers.
    const LOGIN_ERROR_MAP = {
      invalid_credentials: '用户名或密码错误',
      account_locked: '账户已锁定，请 15 分钟后再试',
      too_many_attempts: '尝试次数过多，请几分钟后再试',
    };
    async function doLogin() {
      if (loading.value) return; // Enter key on either input can double-submit
      loginError.value = '';
      if (!loginUser.value || !loginPass.value) { loginError.value = '请输入用户名和密码。'; return; }
      loading.value = true;
      try {
        const params = new URLSearchParams();
        params.append('user', loginUser.value);
        params.append('password', loginPass.value);
        const d = await api('POST', '/verynginx/login', params);
        loginPass.value = '';
        if (d.ret === 'success') {
          store.loggedIn = true;
          store.user = loginUser.value;
          loginUser.value = '';
          sessionExpiredNotice.value = false; // one-shot kick notice consumed
          await refreshCsrf();
          loadVersion();
          loadConfig();
          syncPolls();
          // Same as the restore path: land on the hash-restored view with data.
          if (shared.navigateTo) await shared.navigateTo(shared.page.value);
        } else {
          loginError.value = LOGIN_ERROR_MAP[d.message] || d.message || '登录失败';
        }
      } catch (e) {
        loginError.value = e.message;
      }
      loading.value = false;
    }


    // ---- Logout ----
    async function doLogout() {
      // Stop all polling; session revocation below clears the loggedIn watcher
      stopAllPolls();
      // Revoke the session server-side FIRST, while the CSRF token is still
      // valid — the /logout POST needs the X-CSRF-Token header. Clearing the
      // token before the request would make the server reject it (401) and
      // leave the session un-revoked. The session cookie is HttpOnly
      // (api/auth.lua:172), so a JS document.cookie wipe can't remove it; only
      // the server-side revoke makes a page refresh stay logged out.
      try { await api('POST', '/verynginx/logout'); } catch (_) {}
      // Now drop the client CSRF token so a re-login can't reuse the stale one
      if (shared.clearCsrf) shared.clearCsrf();
      store.loggedIn = false;
      store.user = null;
      // Per-session data wipe happens in the store.loggedIn watcher
      // (runLogoutHooks) so server-side expiry gets the same cleanup.
    }

    // ---- Exports ----
    ctx('parsePrometheus', parsePrometheus);
    ctx('loadVersion', loadVersion);
    ctx('loadOverview', loadOverview);
    view('loadStats', loadStats);
    view('loadStatus', loadStatus);
    view('loadConfig', loadConfig);
    view('refreshConfig', refreshConfig);
    ctx('loadHealth', loadHealth);
    view('loadDictUsage', loadDictUsage);
    view('loadTopPaths', loadTopPaths);
    view('doLogin', doLogin);
    view('doLogout', doLogout);
    view('formatTime', formatTime);
    view('formatBytes', formatBytes);
    view('calcSuccess', calcSuccess);
    view('successClass', successClass);
    view('summarizeRule', summarizeRule);
    view('actionClass', actionClass);

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();