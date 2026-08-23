// vn-iploc.js - GeoIP module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-frequency.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vniploc'] = function createvniplocModule(shared) {
        const { ctx, view, api, isValidIpLiteral, showToast, showConfirm } = shared;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- GeoIP State ----
    // Single source of truth for mirror ids/URLs (load maps URL→id, save maps
    // id→URL — two hand-maintained copies drifted once already).
    const MIRRORS = [
      { id: 'p3terx', url: 'https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb' },
      { id: 'loyalsoldier_raw', url: 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb' },
      { id: 'loyalsoldier_release', url: 'https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb' },
    ];
    const geoipLookupIP = ref('');
    const geoipLookupResult = ref(null);
    const geoipStats = ref([]);
    const geoipMaxCount = computed(() => (geoipStats.value.length ? geoipStats.value[0].count : 0));
    const geoipConfig = ref({ enable: false, geodb_path: '', whitelistStr: '', blocklistStr: '', blockContinentsStr: '', use_cdn: false, auto_update: true, update_interval_hours: 168, mirror: 'auto', custom_mirror_url: '', license_key: '' });
    const geoipStatus = ref({ available: false, size: 0, last_check: 0, last_update: 0, geodb_path: '' });
    const geoipLoading = ref(false);
    const geoipError = ref('');

    // Stale-response guard for the geoip data loader.
    const gGeoip = shared.createStaleGuard();

    // ---- Load ----
    const geoipStatusError = ref('');
    async function loadGeoIPStatus() {
      geoipStatusError.value = '';
      try {
        const d = await api('GET', '/verynginx/geoip/status');
        if (d.ret === 'success') geoipStatus.value = d.data;
        else geoipStatusError.value = d.message || 'GeoIP 状态加载失败';
      } catch (e) {
        if (e.message !== 'session_expired') geoipStatusError.value = e.message;
      }
    }

    async function loadGeoIP() {
      const tok = gGeoip.mark();
      geoipLoading.value = true;
      geoipError.value = '';
      try {
        const [cfgRes, statsRes] = await Promise.all([
          api('GET', '/verynginx/geoip/config'),
          api('GET', '/verynginx/geoip/stats'),
        ]);
        if (!gGeoip.isCurrent(tok)) return;
        if (cfgRes.ret === 'success') {
          const cfg = cfgRes.data || {};
          // Determine mirror source from config
          let mirror = 'auto';
          let custom_mirror_url = '';
          if (cfg.cdn_url || cfg.update_url) {
            const url = cfg.cdn_url || cfg.update_url;
            const hit = MIRRORS.find(m => m.url === url);
            mirror = hit ? hit.id : 'custom';
            if (!hit) custom_mirror_url = url;
          }
          geoipConfig.value = {
            enable: cfg.enable || false,
            geodb_path: cfg.geodb_path || '',
            whitelistStr: (cfg.whitelist || []).join(','),
            blocklistStr: (cfg.blocklist || []).join(','),
            blockContinentsStr: (cfg.block_continents || []).join(','),
            use_cdn: cfg.use_cdn === true,
            auto_update: cfg.auto_update !== false,
            update_interval_hours: cfg.update_interval_hours || 168,
            mirror, custom_mirror_url,
            license_key: cfg.license_key || '',
          };
        } else {
          geoipError.value = cfgRes.message || 'GeoIP 配置加载失败';
        }
        if (statsRes.ret === 'success') {
          geoipStats.value = Object.entries(statsRes.data || {}).map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count).slice(0, 20);
        }
      } catch (e) {
        if (e.message !== 'session_expired') geoipError.value = e.message;
      } finally {
        if (gGeoip.isCurrent(tok)) geoipLoading.value = false;
      }
    }

    // ---- Lookup ----
    async function lookupGeoIP() {
      if (!geoipLookupIP.value) return;
      const ip = geoipLookupIP.value.trim();
      if (!isValidIpLiteral(ip)) { showToast('IP 格式无效: ' + ip, 'error'); return; }
      try {
        const d = await api('GET', '/verynginx/geoip/lookup?ip=' + encodeURIComponent(ip));
        geoipLookupResult.value = d;
      } catch (e) {
        showToast(e.message || '查询失败', 'error');
      }
    }

    // ---- Save / Update ----
    const geoipSaving = ref(false);
    let geoipSavePending = false;
    async function saveGeoIPConfig() {
      // Serialize with a trailing run: edits made while a save is in flight
      // must not be dropped (the control already shows the new state).
      if (geoipSaving.value) { geoipSavePending = true; return; }
      geoipSaving.value = true;
      do {
        geoipSavePending = false;
        try {
          let cdn_url = '';
          let update_url = '';
          if (geoipConfig.value.mirror === 'custom') {
            update_url = geoipConfig.value.custom_mirror_url || '';
          } else if (geoipConfig.value.mirror !== 'auto') {
            const hit = MIRRORS.find(m => m.id === geoipConfig.value.mirror);
            cdn_url = hit ? hit.url : '';
          }
          const cfg = {
            enable: !!geoipConfig.value.enable,
            geodb_path: geoipConfig.value.geodb_path || '',
            whitelist: geoipConfig.value.whitelistStr.split(',').map(s => s.trim()).filter(s => s),
            blocklist: geoipConfig.value.blocklistStr.split(',').map(s => s.trim()).filter(s => s),
            // Without these the server's schema refills defaults and silently
            // wipes an operator-configured continent block / CDN preference.
            block_continents: (geoipConfig.value.blockContinentsStr || '').split(',').map(s => s.trim().toUpperCase()).filter(s => s),
            use_cdn: !!geoipConfig.value.use_cdn,
            auto_update: !!geoipConfig.value.auto_update,
            update_interval_hours: geoipConfig.value.update_interval_hours || 168,
            cdn_url, update_url,
            license_key: geoipConfig.value.license_key || '',
          };
          const d = await api('PUT', '/verynginx/geoip/config', cfg);
          if (d.ret === 'success') showToast('GeoIP 配置已保存', 'success');
          else {
            showToast(d.message || '保存失败', 'error');
            await loadGeoIP(); // resync form with what the server actually kept
          }
        } catch (e) {
          showToast(e.message || '保存失败', 'error');
          await loadGeoIP();
        }
      } while (geoipSavePending);
      geoipSaving.value = false;
    }

    const geoipUpdating = ref(false);
    async function triggerGeoIPUpdate() {
      if (geoipUpdating.value) return;
      if (!await showConfirm({
        title: '更新 GeoIP 数据库',
        message: '立即从数据源下载并替换 GeoIP 数据库？现有 .mmdb 将被覆盖。',
        type: 'danger',
        requireInput: true,
        inputLabel: '请输入 "UPDATE" 确认',
        inputExpected: 'UPDATE',
      })) return;
      geoipUpdating.value = true;
      try {
        const d = await api('POST', '/verynginx/geoip/update');
        if (d.ret === 'success') {
          showToast(d.message || '更新成功', 'success');
          await loadGeoIP();
          // Fetch fresh status (includes DB info)
          const s = await api('GET', '/verynginx/geoip/status');
          if (s.ret === 'success') geoipStatus.value = s.data;
        } else {
          showToast(d.message || '更新失败', 'error');
        }
      } catch (e) {
        showToast(e.message || '更新失败', 'error');
      } finally {
        geoipUpdating.value = false;
      }
    }

    // ---- Exports ----
    view('geoipLookupIP', geoipLookupIP);
    view('geoipLookupResult', geoipLookupResult);
    view('geoipStats', geoipStats);
    view('geoipMaxCount', geoipMaxCount);
    view('geoipConfig', geoipConfig);
    view('geoipStatus', geoipStatus);
    view('geoipStatusError', geoipStatusError);
    view('geoipLoading', geoipLoading);
    view('geoipUpdating', geoipUpdating);
    view('geoipError', geoipError);
    ctx('loadGeoIPStatus', loadGeoIPStatus);
    view('loadGeoIP', loadGeoIP);
    view('lookupGeoIP', lookupGeoIP);
    view('saveGeoIPConfig', saveGeoIPConfig);
    view('triggerGeoIPUpdate', triggerGeoIPUpdate);

    // Wipe per-session GeoIP data on logout.
    shared.onLogout(() => {
      geoipLookupResult.value = null;
      geoipLookupIP.value = '';
      geoipStats.value = [];
      geoipStatus.value = { available: false, size: 0, last_check: 0, last_update: 0, geodb_path: '' };
      geoipError.value = '';
      geoipStatusError.value = '';
      geoipConfig.value = { enable: false, geodb_path: '', whitelistStr: '', blocklistStr: '', blockContinentsStr: '', use_cdn: false, auto_update: true, update_interval_hours: 168, mirror: 'auto', custom_mirror_url: '', license_key: '' };
    });

        // Module initialization (if any)
        // No return needed; ctx()/view() calls register everything
    };
})();