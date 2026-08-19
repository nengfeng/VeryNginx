// vn-dashboard.js - Dashboard module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-common.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vndashboard'] = function createvndashboardModule(shared) {
        const { ctx, view, api, store, page, dashTab, advTab, cfgTab, loading, loginUser, loginPass, loginError, status, connHistory, cfg, healthData, overview, dictUsage, rawJson, statsData, statsType, statsError, versionInfo, topPaths, refreshCsrf, showToast, registerPoll, syncPolls, stopAllPolls } = shared;
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
              const d = (o.dicts || []).find(x => x.name === lb.dict);
              if (d) { d.used = val; if (!d.cap) { const p = parsed['shared_dict_capacity_bytes']; if (p) for (const [lk, v] of Object.entries(p)) { const l = JSON.parse(lk); if (l.dict === lb.dict) d.cap = v; } } }
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

    // Advanced tab load (fingerprints / audit) - late-bound via shared
    watch([page, advTab], ([p, d]) => {
      if (p === 'advanced') {
        if (d === 'fingerprints') { if (shared.loadFingerprints) shared.loadFingerprints(); }
        else { if (shared.loadAudit) shared.loadAudit(); }
      }
    });

    // Config tab: dict usage on system tab (polling handled by registry)
    watch(cfgTab, (tab) => {
      if (tab === 'system') loadDictUsage();
    });

    // Stop all polling when the session ends
    watch(() => store.loggedIn, (loggedIn) => {
      if (!loggedIn) stopAllPolls();
    });

    // Kick off on first mount if already logged in (e.g. session cookie)
    Vue.nextTick(() => {
      if (store.loggedIn) {
        loadVersion();
        syncPolls();
      }
    });


    // ---- Stats ----
    async function loadStats() {
      statsError.value = '';
      try {
        statsData.value = await api('GET', `/verynginx/summary?type=${statsType.value}`);
      } catch (e) {
        statsError.value = e.message;
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
      const p = parseFloat(calcSuccess(v));
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
    async function loadData() {
      loadVersion();
      await Promise.all([loadStatus(), loadConfig()]);
      loadHealth();
    }

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
      } catch (e) {
        showToast('Failed to load config: ' + e.message, 'error');
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
    async function doLogin() {
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
          await refreshCsrf();
          loadData();
          syncPolls();
        } else {
          loginError.value = d.message || '登录失败';
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
      // Revoke session server-side (best-effort)
      try { await api('POST', '/verynginx/logout'); } catch (_) {}
      document.cookie = 'verynginx_session=; Path=/; Max-Age=0';
      store.loggedIn = false;
      store.user = null;
    }

    // ---- Exports ----
    ctx('parsePrometheus', parsePrometheus);
    ctx('loadVersion', loadVersion);
    ctx('loadOverview', loadOverview);
    view('loadStats', loadStats);
    ctx('loadData', loadData);
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