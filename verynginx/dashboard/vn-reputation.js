// vn-reputation.js - IP reputation module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-iploc.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vnreputation'] = function createvnreputationModule(shared) {
        const { ctx, view, api, isValidIpLiteral, showConfirm, showToast, showUndoToast } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- Reputation State ----
    const repStats = ref(null);
    const repFlagged = ref([]);
    const repWhitelist = ref([]);
    const repError = ref('');
    const repNewWhitelist = ref('');
    const repLookupIP = ref('');
    const repLookupResult = ref(null);
    const repClearBusy = ref({});

    // Flagged-row detail modal: overview+reason / related hits / IP info.
    // Tab data is cached per IP (…Ip fields) and refetched on each activation.
    const repDetailModal = reactive({
      show: false, ip: '', tab: 'overview',
      loading: false, error: '', data: null, dataIp: '',
      hits: null, hitsIp: '', hitsLoading: false, hitsError: '',
      geo: null, geoIp: '', geoLoading: false, geoError: '',
    });
    const gRepDetail = shared.createStaleGuard();
    const gRepDetailHits = shared.createStaleGuard();
    const gRepDetailGeo = shared.createStaleGuard();

    // Human labels for reputation signal types (breakdown display).
    const SIGNAL_LABELS = {
      waf_block: 'WAF 拦截',
      waf_challenge: 'WAF 挑战',
      not_found: '404 异常',
      challenge_fail: '挑战失败',
      geoip_block: 'GeoIP 封禁',
      fingerprint_block: '指纹封禁',
      fingerprint_challenge: '指纹挑战',
    };
    function signalLabel(s) {
      return SIGNAL_LABELS[s] || s;
    }

    // Stale-response guard for the reputation data loader.
    const gRepData = shared.createStaleGuard();

    // ---- Load ----
    async function loadRepData() {
      const tok = gRepData.mark();
      repError.value = '';
      try {
        const [sd, fd, wd] = await Promise.all([
          api('GET', '/verynginx/reputation/stats'),
          api('GET', '/verynginx/reputation/flagged'),
          api('GET', '/verynginx/reputation/whitelist'),
        ]);
        if (!gRepData.isCurrent(tok)) return;
        repStats.value = sd.data;
        repFlagged.value = fd.data || [];
        repWhitelist.value = wd.data || [];
      } catch (e) {
        if (gRepData.isCurrent(tok)) repError.value = e.message;
      }
    }

    async function repClear(ip) {
      if (!await showConfirm({
        title: '清除 IP 声誉',
        message: `将清除 IP ${ip} 的所有声誉信号槽和待处理状态。\n\n`
          + '清除后该 IP 的分数归零，不再触发自动挑战或封禁，直到下一次被 WAF 命中累积新分数。\n'
          + '如果该 IP 当前正在封禁中，此操作仅清除声誉数据，内核封禁条目需单独清除。',
        type: 'danger',
        requireInput: true,
        inputLabel: `请输入 IP 地址 ${ip} 确认`,
        inputExpected: String(ip),
      })) return;
      repClearBusy.value[ip] = true;
      try {
        await api('POST', '/verynginx/reputation/clear?ip=' + encodeURIComponent(ip));
        // Also close the detail modal if this clear came from it.
        if (repDetailModal.show && repDetailModal.ip === ip) repDetailModal.show = false;
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      } finally {
        repClearBusy.value[ip] = false;
      }
    }

    async function repAddWhitelist() {
      const ip = repNewWhitelist.value.trim();
      if (!ip) return;
      // Client-side IP format validation (allows CIDR prefix for whitelist)
      if (!isValidIpLiteral(ip, true)) { repError.value = 'IP 格式无效: ' + ip; return; }
      try {
        await api('POST', '/verynginx/reputation/whitelist', { ip });
        repNewWhitelist.value = '';
        repError.value = '';
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repRemoveWhitelist(ip) {
      if (!await showConfirm({
        title: '移除白名单',
        message: `从白名单中移除 ${ip}。\n\n`
          + '移除后该 IP 将重新接受声誉评分，触发 WAF 规则，并可能被自动封禁。\n'
          + '如果您是在排查误封后想恢复该 IP 的正常风控，请确认这是预期操作。',
        type: 'danger',
      })) return;
      try {
        await api('DELETE', '/verynginx/reputation/whitelist?ip=' + encodeURIComponent(ip));
        showUndoToast(`已从白名单移除 ${ip}`, async () => {
          await api('POST', '/verynginx/reputation/whitelist', { ip });
          showToast('已撤销：重新加入白名单 ' + ip, 'success');
          loadRepData();
        });
        loadRepData();
      } catch (e) {
        repError.value = e.message;
      }
    }

    // ---- Crawler range fetch (panel button) ----
    // The notice that says the list is empty is the one place an operator
    // without a shell can act on it, so the fetch lives here as well as in
    // tools/fetch_crawler_ips.py.
    const repFetchBusy = ref(false);
    const repFetchResult = ref(null);
    const repFetchPartial = ref(false);

    async function repFetchCrawlers(apply) {
      if (repFetchBusy.value) return;
      if (apply && !await showConfirm({
        title: '拉取并写入爬虫 IP 段',
        message: '将从各厂商官方地址拉取已公布的爬虫网段，合并写入 '
          + 'ip_reputation.crawler_ip_whitelist。\n\n'
          + '• 只在至少一个厂商返回可用名单时才写入；全部失败则原样保留现有名单\n'
          + '• 写入的名单会替换当前列表（不是追加）\n'
          + '• 每个来源的条数与厂商自报的发布时间都会记入配置，便于日后核对',
        type: 'primary',
      })) return;

      repFetchBusy.value = true;
      repFetchResult.value = null;
      repFetchPartial.value = false;
      repError.value = '';
      try {
        const r = await api('POST', '/verynginx/reputation/crawler/fetch',
          apply ? { apply: true } : { apply: false });
        const d = r.data || {};
        repFetchResult.value = d;
        // "Partial" means some vendor answered and some did not. Saying so
        // matters: a silent partial write is indistinguishable from a vendor
        // shrinking its range.
        const rs = d.results || [];
        repFetchPartial.value = rs.some(x => x.ok) && rs.some(x => !x.ok);
        if (d.preview) {
          const got = rs.filter(x => x.ok).length;
          showToast(got
            ? '试拉取完成：' + got + '/' + rs.length + ' 个厂商可达，未写入任何配置'
            : '试拉取完成：没有任何厂商可达，未写入任何配置', got ? 'info' : 'error');
        } else if (d.ok) {
          showToast('已写入 ' + d.written + ' 条网段（原有 ' + d.before + ' 条）', 'success');
          loadRepData();
        }
      } catch (e) {
        repError.value = e.message;
      } finally {
        repFetchBusy.value = false;
      }
    }

    async function repPersist() {
      if (!await showConfirm({
        title: '持久化声誉数据',
        message: '将内存中的 IP 声誉分数和状态写入磁盘。\n\n'
          + '系统会在每 600 秒（10 分钟）自动持久化一次，手动触发通常用于：\n'
          + '• 怀疑数据未同步前的紧急保存\n'
          + '• 配合内核封禁重启前的数据快照\n'
          + '• 故障排查时确认磁盘数据最新。',
        type: 'primary',
      })) return;
      try {
        await api('POST', '/verynginx/reputation/persist');
      } catch (e) {
        repError.value = e.message;
      }
    }

    async function repLookup() {
      const ip = repLookupIP.value.trim();
      if (!ip) return;
      if (!isValidIpLiteral(ip)) { repError.value = 'IP 格式无效: ' + ip; return; }
      repLookupResult.value = null;
      try {
        const d = await api('GET', '/verynginx/reputation/score?ip=' + encodeURIComponent(ip));
        repLookupResult.value = d.data;
      } catch (e) {
        repError.value = e.message;
      }
    }

    // ---- Flagged-row detail modal ----
    async function repLoadOverview(ip) {
      const tok = gRepDetail.mark();
      repDetailModal.loading = true;
      repDetailModal.error = '';
      try {
        const d = await api('GET', '/verynginx/reputation/score?ip=' + encodeURIComponent(ip));
        if (d.ret === 'success') {
          if (gRepDetail.isCurrent(tok)) {
            repDetailModal.data = d.data;
            repDetailModal.dataIp = ip;
          }
        } else if (gRepDetail.isCurrent(tok)) {
          repDetailModal.error = d.message || '查询失败';
          repDetailModal.data = null;
        }
      } catch (e) {
        if (e.message === 'session_expired') throw e;
        if (gRepDetail.isCurrent(tok)) repDetailModal.error = e.message;
      }
      if (gRepDetail.isCurrent(tok)) repDetailModal.loading = false;
    }

    async function repLoadHits(ip) {
      const tok = gRepDetailHits.mark();
      repDetailModal.hitsLoading = true;
      repDetailModal.hitsError = '';
      try {
        const d = await api('GET', '/verynginx/waf/hits/by-ip?ip=' + encodeURIComponent(ip));
        if (gRepDetailHits.isCurrent(tok)) {
          if (d.ret === 'success') {
            repDetailModal.hits = Array.isArray(d.data) ? d.data : [];
            repDetailModal.hitsIp = ip;
          } else {
            repDetailModal.hitsError = d.message || '命中记录加载失败';
            repDetailModal.hits = [];
          }
        }
      } catch (e) {
        if (e.message === 'session_expired') throw e;
        if (gRepDetailHits.isCurrent(tok)) {
          repDetailModal.hitsError = e.message;
          repDetailModal.hits = [];
        }
      }
      if (gRepDetailHits.isCurrent(tok)) repDetailModal.hitsLoading = false;
    }

    async function repLoadGeo(ip) {
      const tok = gRepDetailGeo.mark();
      repDetailModal.geoLoading = true;
      repDetailModal.geoError = '';
      repDetailModal.geo = null;
      try {
        const d = await api('GET', '/verynginx/geoip/lookup?ip=' + encodeURIComponent(ip));
        if (gRepDetailGeo.isCurrent(tok)) {
          if (d.ret === 'success' && d.data) {
            repDetailModal.geo = d.data;
            repDetailModal.geoIp = ip;
          } else {
            // ret=failed → DB unavailable (d.message has the reason);
            // ret=success + null data → IP simply absent from the database.
            repDetailModal.geoError = d.message || 'GeoIP 库中无此 IP';
          }
        }
      } catch (e) {
        if (e.message === 'session_expired') throw e;
        if (gRepDetailGeo.isCurrent(tok)) repDetailModal.geoError = e.message;
      }
      if (gRepDetailGeo.isCurrent(tok)) repDetailModal.geoLoading = false;
    }

    // Open (or re-focus) the detail modal for ip on the given tab. Switching
    // to a different IP resets the cached tab data so nothing flashes from
    // the previous IP; the requested tab always refetches for fresh numbers.
    async function repOpenDetail(ip, tab) {
      const t = tab || 'overview';
      if (repDetailModal.dataIp !== ip) {
        repDetailModal.data = null;
        repDetailModal.hits = null;
        repDetailModal.geo = null;
        repDetailModal.hitsIp = '';
        repDetailModal.geoIp = '';
        repDetailModal.error = '';
        repDetailModal.hitsError = '';
        repDetailModal.geoError = '';
      }
      repDetailModal.ip = ip;
      repDetailModal.tab = t;
      repDetailModal.show = true;
      repLoadOverview(ip);
      if (t === 'hits') repLoadHits(ip);
      if (t === 'geo') repLoadGeo(ip);
    }

    // One-line summary of the flag-time reason snapshot for the table cell.
    function repReasonText(e) {
      const r = e && e.reason;
      if (!r) return '—';
      const sigs = Array.isArray(r.signals) ? r.signals : [];
      if (!sigs.length) return '标记时无信号记录（手动或联动标记）';
      return sigs.map(s => `${signalLabel(s.signal)}×${s.events}（${s.points}分）`).join(' · ');
    }

    // Compact signal breakdown for the daily flag-log rows; same sorted
    // array shape as the reason snapshot signals.
    function repLogSignals(fl) {
      const sigs = Array.isArray(fl && fl.signals) ? fl.signals : [];
      if (!sigs.length) return '—';
      return sigs.slice(0, 3)
        .map(s => `${signalLabel(s.signal)}×${s.events}`)
        .join(' · ') + (sigs.length > 3 ? ' …' : '');
    }

    // Whitelist shortcut from the detail modal (flag → whitelist is the
    // standard false-positive flow; removal reuses the guarded remover).
    async function repWhitelistToggle(ip) {
      if (repWhitelist.value.includes(ip)) {
        await repRemoveWhitelist(ip);
        if (repDetailModal.show && repDetailModal.ip === ip) repLoadOverview(ip);
        return;
      }
      if (!await showConfirm({
        title: '加入白名单',
        message: `将 ${ip} 加入白名单？\n\n`
          + '加入后该 IP 完全跳过声誉评分，不再被自动挑战或封禁，WAF 规则对其也只记录不拦截。\n'
          + '适用于确认误封后恢复正常流量，或保护自家出口 IP。',
        type: 'primary',
      })) return;
      try {
        await api('POST', '/verynginx/reputation/whitelist', { ip });
        showToast('已加入白名单: ' + ip, 'success');
        loadRepData();
        if (repDetailModal.show && repDetailModal.ip === ip) repLoadOverview(ip);
      } catch (e) {
        repError.value = e.message;
      }
    }

    // ---- Exports ----
    view('repStats', repStats);
    view('repFlagged', repFlagged);
    view('repWhitelist', repWhitelist);
    view('repError', repError);
    view('repNewWhitelist', repNewWhitelist);
    view('repLookupIP', repLookupIP);
    view('repLookupResult', repLookupResult);
    view('repClearBusy', repClearBusy);
    view('loadRepData', loadRepData);
    view('repClear', repClear);
    view('repAddWhitelist', repAddWhitelist);
    view('repRemoveWhitelist', repRemoveWhitelist);
    view('repPersist', repPersist);
    view('repFetchCrawlers', repFetchCrawlers);
    view('repFetchBusy', repFetchBusy);
    view('repFetchResult', repFetchResult);
    view('repFetchPartial', repFetchPartial);
    view('repLookup', repLookup);
    view('repDetailModal', repDetailModal);
    view('repOpenDetail', repOpenDetail);
    view('repReasonText', repReasonText);
    view('repLogSignals', repLogSignals);
    view('signalLabel', signalLabel);
    view('repWhitelistToggle', repWhitelistToggle);

    // Wipe per-session reputation data on logout.
    shared.onLogout(() => {
      repStats.value = null;
      repFlagged.value = [];
      repWhitelist.value = [];
      repError.value = '';
      repLookupResult.value = null;
      repNewWhitelist.value = '';
      repLookupIP.value = '';
      Object.assign(repDetailModal, {
        show: false, ip: '', tab: 'overview',
        loading: false, error: '', data: null, dataIp: '',
        hits: null, hitsIp: '', hitsLoading: false, hitsError: '',
        geo: null, geoIp: '', geoLoading: false, geoError: '',
      });
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();