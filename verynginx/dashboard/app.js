// app.js - Main entry point for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Namespace for module factories
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};
    window.VN._dups = [];

    const viewExports = new Map();   // template render scope (setup() return)
    const shared = {};               // internal cross-module registry

    // ctx(): internal cross-module sharing only. Registers a value that later
    // modules may read via `const { ... } = shared`, but NOT template-visible.
    function ctx(name, value) {
        if (name in shared) {
            const msg = 'Duplicate shared export: ' + name;
            console.error('[VeryNginx] ' + msg);
            window.VN._dups.push(msg);
        }
        shared[name] = value;
    }

    // view(): template-visible (also shared). Only what the template actually
    // references belongs here - keeping the render scope small avoids the
    // "302 names in one scope" collision hazard.
    function view(name, value) {
        ctx(name, value);
        if (viewExports.has(name)) {
            const msg = 'Duplicate view export: ' + name;
            console.error('[VeryNginx] ' + msg);
            window.VN._dups.push(msg);
        }
        viewExports.set(name, value);
    }

    ctx('ctx', ctx);
    ctx('view', view);

    // Initialize modules in dependency order:
    // 1. Common (shared state + core utilities)
    // 2. Domain modules (may read earlier modules' exports from `shared`)
    const domainModules = [
        'vncommon',
        'vndashboard',
        'vnconfig',
        'vnwaf',
        'vnfrequency',
        'vniploc',
        'vnreputation',
        'vnadvanced',
        'vnkb',
    ];
    for (const name of domainModules) {
        if (window.VN.modules[name]) {
            window.VN.modules[name](shared);
        }
    }

    // ---- Hash router (#/page/tab/subtab) ----
    // Serializes the view state into the URL so refresh/back/bookmark/share
    // keep the user's position (e.g. #/waf/attacks/hits). Pure frontend: the
    // writer is a single watcher over every navigation ref, so inline template
    // tab switches and navigateTo() are both captured; the reader applies the
    // parsed segments back onto those same refs, and existing per-page/tab
    // watchers then handle data loading.
    // Skipped when location is unavailable (e.g. the Node-based init gate).
    if (typeof window !== 'undefined' && window.location) {
      const routeRefs = {
        page: shared.page, groupPage: shared.groupPage,
        dashTab: shared.dashTab, cfgTab: shared.cfgTab,
        advTab: shared.advTab, wafTab: shared.wafTab, wafRuleView: shared.wafRuleView,
        wafAttackView: shared.wafAttackView, kbTab: shared.kbTab,
      };
      // Group membership: which top-level section each sub-page belongs to.
      const PAGE_GROUP = {
        dashboard: 'dashboard', config: 'config', waf: 'protect', frequency: 'protect',
        reputation: 'protect', geoip: 'system', kb: 'system', advanced: 'advanced', about: 'about',
      };
      // Backward-compat: treat bare sub-page hashes (e.g. #/waf) as group+page.
      const KNOWN_SUB = Object.keys(PAGE_GROUP);
      const KNOWN_GROUPS = ['dashboard', 'protect', 'system', 'config', 'advanced', 'about'];
      const isKnown = (s) => KNOWN_GROUPS.includes(s) || KNOWN_SUB.includes(s);

      const buildHash = () => {
        const gp = routeRefs.groupPage.value;
        const p = routeRefs.page.value;
        const segs = [gp, p];
        if (p === 'dashboard') segs.push(routeRefs.dashTab.value);
        else if (p === 'config') segs.push(routeRefs.cfgTab.value);
        else if (p === 'advanced') segs.push(routeRefs.advTab.value);
        else if (p === 'waf') {
          segs.push(routeRefs.wafTab.value);
          if (routeRefs.wafTab.value === 'rules') segs.push(routeRefs.wafRuleView.value);
          if (routeRefs.wafTab.value === 'attacks') segs.push(routeRefs.wafAttackView.value);
        } else if (p === 'kb') segs.push(routeRefs.kbTab.value);
        return '#/' + segs.map(s => encodeURIComponent(s)).join('/');
      };

      const applyHash = () => {
        const raw = window.location.hash.replace(/^#\/?/, '');
        if (!raw) {
          // Empty hash: reset to dashboard (default group + page).
          routeRefs.groupPage.value = 'dashboard';
          routeRefs.page.value = 'dashboard';
          return;
        }
        const segs = raw.split('/').map(s => decodeURIComponent(s));
        const seg0 = segs[0];
        let group, page;
        if (isKnown(seg0) && KNOWN_GROUPS.includes(seg0)) {
          // New format: #/protect/waf or #/system/kb
          group = seg0;
          page = segs[1] || group; // fallback keeps group visible
          // If second seg is also a known group, treat as legacy bare-page hash.
          if (KNOWN_GROUPS.includes(page)) { page = page; group = PAGE_GROUP[page] || group; }
        } else if (KNOWN_SUB.includes(seg0)) {
          // Legacy bare sub-page hash: #/waf → treat as belonging to its group.
          page = seg0;
          group = PAGE_GROUP[page] || 'dashboard';
        } else {
          return;
        }
        // A PAGE segment change unmounts any open editor modal (they live in
        // per-page v-if blocks). History navigation and address-bar edits
        // arrive here without passing navigateTo's unsaved-changes guard, so
        // run the same check: confirm first; on reject snap the URL back to
        // the current view — that echo re-enters applyHash with refs already
        // equal and stops (no loop).
        if (page !== routeRefs.page.value && shared.collectUnsaved && shared.collectUnsaved().length) {
          const labels = shared.collectUnsaved().join('、');
          const restore = buildHash();
          shared.showConfirm({
            title: '未保存的更改',
            message: `${labels}有未保存的更改，离开将丢失。确定放弃并离开？`,
            type: 'warning',
          }).then((ok) => {
            if (ok) {
              if (shared.discardUnsaved) shared.discardUnsaved();
              applyHash();
            } else if (window.location.hash !== restore) {
              window.location.hash = restore;
            }
          });
          return;
        }
        const set = (ref, v) => { if (ref && v && ref.value !== v) ref.value = v; };
        set(routeRefs.groupPage, group);
        set(routeRefs.page, page);
        if (page === 'dashboard') set(routeRefs.dashTab, segs[2]);
        else if (page === 'config') set(routeRefs.cfgTab, segs[2]);
        else if (page === 'advanced') set(routeRefs.advTab, segs[2]);
        else if (page === 'waf') {
          set(routeRefs.wafTab, segs[2]);
          if (segs[2] === 'rules') set(routeRefs.wafRuleView, segs[3]);
          if (segs[2] === 'attacks') set(routeRefs.wafAttackView, segs[3]);
        } else if (page === 'kb') set(routeRefs.kbTab, segs[2]);
      };

      // Writer: any navigation change updates the URL. PAGE switches push a
      // history entry (Back steps between pages); TAB switches only replace
      // the current entry so rapid tab-hopping doesn't bury the history
      // stack. replaceState doesn't fire hashchange — fine here, the refs
      // already hold the state the URL now describes.
      Vue.watch(
        [routeRefs.page, routeRefs.dashTab, routeRefs.cfgTab, routeRefs.advTab,
         routeRefs.wafTab, routeRefs.wafRuleView, routeRefs.wafAttackView, routeRefs.kbTab],
        (vals, olds) => {
          const h = buildHash();
          if (window.location.hash === h) return;
          if (vals[0] !== olds[0]) window.location.hash = h;
          else window.history.replaceState(null, '', h);
        }
      );
      window.addEventListener('hashchange', applyHash);
      // Restore position before mount so the first render already shows the
      // bookmarked view instead of flashing the overview page.
      applyHash();
    }

    // Mount Vue app
    const app = Vue.createApp({
        setup() {
            return Object.fromEntries(viewExports);
        }
    });

    // In prod builds Vue swallows render/computed errors into a silent white
    // screen. Surface them as a toast so the failure is visible instead.
    app.config.errorHandler = (err, instance, info) => {
        const msg = err && err.message ? err.message : String(err);
        try {
            if (shared.showToast) {
                shared.showToast('渲染错误: ' + msg + (info ? ' (' + info + ')' : ''), 'error');
            }
        } catch (e) {
            console.error('errorHandler failed', e);
        }
        console.error('Vue render error' + (info ? ' [' + info + ']' : ''), err);
    };

    app.mount('#app');

})();