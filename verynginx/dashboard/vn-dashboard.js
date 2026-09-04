// vn-dashboard.js - Dashboard module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-common.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vndashboard'] = function createvndashboardModule(shared) {
        const { ctx, view, api, store, page, dashTab, advTab, cfgTab, loading, loginUser, loginPass, loginError, sessionExpiredNotice, status, connHistory, cfg, healthData, overview, dictUsage, rawJson, statsData, statsType, statsError, versionInfo, topPaths, refreshCsrf, showToast, registerPoll, syncPolls, stopAllPolls, refreshPollActivePages, asList } = shared;
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
        // Main data source failed: keep the last good overview so the page
        // never shows a silent all-zero "all quiet" picture. The health
        // summary card surfaces the error instead.
        if (gOverview.isCurrent(tok)) overviewError.value = e.message;
        return;
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
      overviewError.value = '';
    }


    // ---- Auto-refresh polling ----
    // Every poller lives in the central registry (vn-common) and declares an
    // `active()` predicate. A single [page, dashTab, cfgTab] watcher reconciles
    // all pollers, so navigation can never leak an interval.
    registerPoll('status', {
        active: () => page.value === 'dashboard' && dashTab.value === 'status',
        interval: 3000,
        load: loadStatus,
        pages: ['dashboard'],
    });
    registerPoll('overview', {
        active: () => page.value === 'dashboard' && dashTab.value === 'overview',
        interval: 5000,
        load: loadOverview,
        pages: ['dashboard'],
    });
    registerPoll('wafTrend', {
        active: () => page.value === 'dashboard' && dashTab.value === 'overview',
        interval: 30000,
        load: loadWafTrend,
        pages: ['dashboard'],
    });
    registerPoll('health', {
        active: () => page.value === 'config' && cfgTab.value === 'upstreams',
        interval: 10000,
        load: loadHealth,
        pages: ['config'],
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
        refreshPollActivePages();
        // Hash routing may have restored a non-default view before mount; its
        // page-change watchers never fired, so run the per-page loaders once.
        if (shared.navigateTo) await shared.navigateTo(shared.page.value);
      }
    });


    // ---- Stats ----
    const gStats = shared.createStaleGuard();
    const gOverview = shared.createStaleGuard();
    const gWafTrend = shared.createStaleGuard();
    const overviewError = ref('');
    const statusError = ref('');
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


    // ---- WAF attack trend (baseline comparison) ----
    // 2h window / 15min buckets = 8 buckets: current hour vs previous hour.
    // A dedicated 30s poller keeps the 5s overview poller light.
    const wafTrendData = ref([]);
    async function loadWafTrend() {
      const tok = gWafTrend.mark();
      try {
        const d = await api('GET', '/verynginx/waf/timeline?hours=2&bucket=15');
        if (!gWafTrend.isCurrent(tok)) return;
        if (d.ret === 'success' && d.data && Array.isArray(d.data.buckets)) {
          wafTrendData.value = asList(d.data.buckets).map((b) => {
            let sum = 0;
            for (const c in (b.counts || {})) sum += b.counts[c];
            return sum;
          });
        }
      } catch (e) {
        // Trend is a secondary view; on failure the card simply stays hidden.
      }
    }

    const wafTrend = computed(() => {
      const arr = wafTrendData.value;
      if (!arr || arr.length < 4) return { curr: 0, prev: 0, pct: null, dir: 'flat' };
      const half = Math.floor(arr.length / 2);
      let prev = 0, curr = 0;
      for (let i = 0; i < half; i++) prev += arr[i];
      for (let i = arr.length - half; i < arr.length; i++) curr += arr[i];
      const pct = prev > 0 ? Math.round((curr - prev) / prev * 100) : null;
      const dir = curr > prev ? 'up' : (curr < prev ? 'down' : 'flat');
      return { curr, prev, pct, dir };
    });

    const wafTrendLabel = computed(() => {
      const t = wafTrend.value;
      if (t.curr === 0 && t.prev === 0) return '';
      if (t.pct === null) {
        // pct null <=> prev === 0; since (curr===0 && prev===0) is caught above,
        // curr must be > 0 here, so dir is always 'up'.  The '' branch is dead
        // code — kept implicitly by dropping the else.
        return '↑ 上一小时无命中，本小时新增 ' + t.curr + ' 次';
      }
      const arrow = t.dir === 'up' ? '↑' : (t.dir === 'down' ? '↓' : '→');
      return arrow + ' 较上一小时 ' + Math.abs(t.pct) + '%';
    });

    const wafTrendSpark = computed(() => {
      const pts = wafTrendData.value;
      if (pts.length < 2) return '';
      const max = Math.max(...pts, 1);
      const w = 100 / (pts.length - 1);
      // Reserve 5% margin at top and bottom so the polyline stroke (which
      // extends ~half its width beyond the point coords) is not clipped at the
      // viewBox edges when all values are equal or at the maximum.
      // 5% top margin, 5% bottom margin: y = 5 + (1 - v/max) * 90
      // = 95 - v/max * 90, so v=0 → y=95 (bottom), v=max → y=5 (top).
      return pts.map((v, i) => `${(i * w).toFixed(1)},${(5 + (1 - v / max) * 90).toFixed(1)}`).join(' ');
    });

    const hasWafTrend = computed(() => {
      const t = wafTrend.value;
      return (t.curr + t.prev) > 0;
    });


    // ---- Health summary (one-line verdict for the overview page) ----
    // Priority: helper down > data unavailable > upstream unhealthy >
    // attack spike > flagged IPs > dict pressure > all clear.
    const healthSummary = computed(() => {
      const o = overview.value || {};
      const kb = shared.kbStatus && shared.kbStatus.value;
      const kbState = (kb && kb.health && kb.health.state) || 'unknown';
      // Read from effective.global_mode (live), not configured.mode (draft).
      // effective.global_mode = 'disabled' when enabled=false regardless of
      // what mode is configured — using configured.mode would lie and say
      // "拦截规则已生效" even while the kernel block is completely off.
      const eff = (kb && kb.effective) || {};
      const globalMode = eff.global_mode || 'disabled';
      if (kbState === 'unreachable') {
        return { level: 'err', text: '内核封禁 Helper 无法连接，内核层拦截已停摆（应用层拦截仍生效）。请到 系统 → 内核封禁 查看 Helper 状态。' };
      }
      if (kbState === 'degraded') {
        return { level: 'warn', text: '内核封禁 Helper 已降级，部分内核层操作可能失败。请到 系统 → 内核封禁 查看详情。' };
      }
      if (overviewError.value) {
        return { level: 'err', text: '监控数据获取失败（' + overviewError.value + '），下方数字可能过期或为空。' };
      }
      if (o.up_total > 0 && o.up_healthy < o.up_total) {
        return { level: 'warn', text: (o.up_total - o.up_healthy) + ' 个上游节点不健康，转发到这些节点的请求会失败。请到 配置 → 上游 查看节点状态。' };
      }
      const t = wafTrend.value;
      if (t.curr >= 20 && t.prev > 0 && t.pct !== null && t.pct >= 100) {
        return { level: 'warn', text: 'WAF 命中较上一小时上涨 ' + t.pct + '%（本小时 ' + t.curr + ' 次），疑似攻击活动。请到 WAF → 分析 查看命中详情。' };
      }
      if ((o.flagged || 0) > 0) {
        return { level: 'warn', text: o.flagged + ' 个 IP 被声誉系统标记为可疑。请到 防护 → IP 声誉 确认是否需要处理。' };
      }
      const hot = (o.dicts || []).find((d) => d.pct > 80);
      if (hot) {
        return { level: 'warn', text: '共享字典 ' + hot.name + ' 使用率 ' + hot.pct.toFixed(0) + '%，接近上限，可能影响新指标与缓存的写入。' };
      }
      // global_mode drives the live behaviour note; disabled is a distinct
      // state (kernel blocks entirely off) and should not be conflated with observe.
      // Note: disabled is the DEFAULT for fresh installs (helper is optional).
      // Show as 'ok' to avoid permanent yellow bar → alert fatigue. Skip the
      // first paint when kbState is still 'unknown' (API hasn't responded yet)
      // to prevent a flash of the warning before data arrives.
      if (globalMode === 'disabled' && kbState !== 'unknown') {
        return { level: 'ok', text: '内核封禁未启用，当前仅应用层 WAF 生效。可在 系统 → 内核封禁 开启。' };
      }
      const modeNote = globalMode === 'enforce'
        ? '拦截规则已生效'
        : '当前为 observe 观察模式，规则只记录不拦截（可到 系统 → 内核封禁 切换）';
      return { level: 'ok', text: '系统运行正常：' + modeNote + '，过去一小时无攻击峰值。' };
    });


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
        statusError.value = '';
        // Push to connection history ring buffer (max 60 points, 3s each = 3 min)
        const h = connHistory.value;
        h.push(s.connections_active || 0);
        if (h.length > 60) h.shift();
        connHistory.value = [...h];
      } catch (e) {
        // Keep the last good numbers on screen; the error banner tells the
        // user the data may be stale instead of showing a silent 0.
        statusError.value = '连接状态获取失败：' + e.message;
      }
    }

    async function loadConfig() {
      try {
        const d = await api('GET', '/verynginx/config');
        // Sanitize rule-group arrays: config JSON can carry null holes that
        // crash v-for renders reading r.enable etc.
        if (d && d.rule) {
          for (const g of Object.keys(d.rule)) {
            if (Array.isArray(d.rule[g])) d.rule[g] = asList(d.rule[g]);
          }
        }
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
          topPaths.value = asList(d.data);
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
           refreshPollActivePages();
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
    view('statusError', statusError);
    view('wafTrend', wafTrend);
    view('wafTrendLabel', wafTrendLabel);
    view('wafTrendSpark', wafTrendSpark);
    view('hasWafTrend', hasWafTrend);
    view('healthSummary', healthSummary);

    // Wipe per-session data on logout (explicit logout AND server-side expiry).
    shared.onLogout(() => {
      overviewError.value = '';
      statusError.value = '';
      wafTrendData.value = [];
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();