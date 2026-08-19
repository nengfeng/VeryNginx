// vn-geoip.js - GeoIP module for VeryNginx Dashboard
// IIFE pattern for classic script loading. Loaded after vn-frequency.

(function() {
    // Register factory on global namespace
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    window.VN.modules['vngeoip'] = function createvngeoipModule(ctx) {
        const { expose, api, isValidIpLiteral, showToast, showConfirm } = ctx;
        // Vue Composition API
        const { reactive, ref, computed, watch } = Vue;

    // ---- GeoIP State ----
    const geoipLookupIP = ref('');
    const geoipLookupResult = ref(null);
    const geoipStats = ref([]);
    const geoipMaxCount = computed(() => (geoipStats.value.length ? geoipStats.value[0].count : 0));
    const geoipConfig = ref({ enable: false, geodb_path: '', whitelistStr: '', blocklistStr: '', auto_update: true, update_interval_hours: 168, mirror: 'auto', custom_mirror_url: '', license_key: '' });
    const geoipStatus = ref({ available: false, size: 0, last_check: 0, last_update: 0, geodb_path: '' });
    const geoipLoading = ref(false);
    const geoipError = ref('');

    // ---- Load ----
    async function loadGeoIPStatus() {
      try {
        const d = await api('GET', '/verynginx/geoip/status');
        if (d.ret === 'success') geoipStatus.value = d.data;
      } catch (e) {
        // silent - status is non-critical
      }
    }

    async function loadGeoIP() {
      geoipLoading.value = true;
      geoipError.value = '';
      try {
        const [cfgRes, statsRes] = await Promise.all([
          api('GET', '/verynginx/geoip/config'),
          api('GET', '/verynginx/geoip/stats'),
        ]);
        if (cfgRes.ret === 'success') {
          const cfg = cfgRes.data || {};
          // Determine mirror source from config
          let mirror = 'auto';
          let custom_mirror_url = '';
          if (cfg.cdn_url || cfg.update_url) {
            const url = cfg.cdn_url || cfg.update_url;
            const MIRROR_MAP = {
              'https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb': 'p3terx',
              'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb': 'loyalsoldier_raw',
              'https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb': 'loyalsoldier_release',
            };
            mirror = MIRROR_MAP[url] || 'custom';
            if (mirror === 'custom') custom_mirror_url = url;
          }
          geoipConfig.value = {
            enable: cfg.enable || false,
            geodb_path: cfg.geodb_path || '',
            whitelistStr: (cfg.whitelist || []).join(','),
            blocklistStr: (cfg.blocklist || []).join(','),
            auto_update: cfg.auto_update !== false,
            update_interval_hours: cfg.update_interval_hours || 168,
            mirror, custom_mirror_url,
            license_key: cfg.license_key || '',
          };
        } else {
          geoipError.value = cfgRes.message || 'Failed to load geoip config';
        }
        if (statsRes.ret === 'success') {
          geoipStats.value = Object.entries(statsRes.data || {}).map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count).slice(0, 20);
        }
      } catch (e) {
        if (e.message !== 'session_expired') geoipError.value = e.message;
      } finally {
        geoipLoading.value = false;
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
        showToast(e.message || 'Lookup failed', 'error');
      }
    }

    // ---- Save / Update ----
    async function saveGeoIPConfig() {
      try {
        const MIRROR_URLS = {
          p3terx: 'https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb',
          loyalsoldier_raw: 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb',
          loyalsoldier_release: 'https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb',
        };
        let cdn_url = '';
        let update_url = '';
        if (geoipConfig.value.mirror === 'custom') {
          update_url = geoipConfig.value.custom_mirror_url || '';
        } else if (geoipConfig.value.mirror !== 'auto') {
          cdn_url = MIRROR_URLS[geoipConfig.value.mirror] || '';
        }
        const cfg = {
          enable: !!geoipConfig.value.enable,
          geodb_path: geoipConfig.value.geodb_path || '',
          whitelist: geoipConfig.value.whitelistStr.split(',').map(s => s.trim()).filter(s => s),
          blocklist: geoipConfig.value.blocklistStr.split(',').map(s => s.trim()).filter(s => s),
          auto_update: !!geoipConfig.value.auto_update,
          update_interval_hours: geoipConfig.value.update_interval_hours || 168,
          cdn_url, update_url,
          license_key: geoipConfig.value.license_key || '',
        };
        const d = await api('PUT', '/verynginx/geoip/config', cfg);
        if (d.ret === 'success') showToast('GeoIP 配置已保存', 'success');
        else showToast(d.message || '保存失败', 'error');
      } catch (e) {
        showToast(e.message || '保存失败', 'error');
      }
    }

    async function triggerGeoIPUpdate() {
      if (!await showConfirm({
        title: '更新 GeoIP 数据库',
        message: '立即从数据源下载并替换 GeoIP 数据库？现有 .mmdb 将被覆盖。',
        type: 'danger',
        requireInput: true,
        inputLabel: '请输入 "UPDATE" 确认',
        inputExpected: 'UPDATE',
      })) return;
      try {
        const d = await api('POST', '/verynginx/geoip/update');
        if (d.ret === 'success') {
          showToast(d.message || 'Update successful', 'success');
          await loadGeoIP();
          // Fetch fresh status (includes DB info)
          const s = await api('GET', '/verynginx/geoip/status');
          if (s.ret === 'success') geoipStatus.value = s.data;
        } else {
          showToast(d.message || 'Update failed', 'error');
        }
      } catch (e) {
        showToast(e.message || 'Update failed', 'error');
      }
    }

    // ---- Exports ----
    expose('geoipLookupIP', geoipLookupIP);
    expose('geoipLookupResult', geoipLookupResult);
    expose('geoipStats', geoipStats);
    expose('geoipMaxCount', geoipMaxCount);
    expose('geoipConfig', geoipConfig);
    expose('geoipStatus', geoipStatus);
    expose('geoipLoading', geoipLoading);
    expose('geoipError', geoipError);
    expose('loadGeoIPStatus', loadGeoIPStatus);
    expose('loadGeoIP', loadGeoIP);
    expose('lookupGeoIP', lookupGeoIP);
    expose('saveGeoIPConfig', saveGeoIPConfig);
    expose('triggerGeoIPUpdate', triggerGeoIPUpdate);

        // Module initialization (if any)
        // No return needed; expose() calls register everything
    };
})();