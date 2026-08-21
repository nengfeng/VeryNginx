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
        'vngeoip',
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
        page: shared.page, dashTab: shared.dashTab, cfgTab: shared.cfgTab,
        advTab: shared.advTab, wafTab: shared.wafTab, wafRuleView: shared.wafRuleView,
        wafAttackView: shared.wafAttackView, kbTab: shared.kbTab,
      };
      const KNOWN_PAGES = ['dashboard', 'config', 'waf', 'frequency', 'reputation', 'geoip', 'advanced', 'kb', 'about'];

      const buildHash = () => {
        const p = routeRefs.page.value;
        const segs = [p];
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
        if (!raw) return;
        const segs = raw.split('/').map(s => decodeURIComponent(s));
        if (!KNOWN_PAGES.includes(segs[0])) return;
        // A PAGE segment change unmounts any open editor modal (they live in
        // per-page v-if blocks). History navigation and address-bar edits
        // arrive here without passing navigateTo's unsaved-changes guard, so
        // run the same check: confirm first; on reject snap the URL back to
        // the current view — that echo re-enters applyHash with refs already
        // equal and stops (no loop).
        if (segs[0] !== routeRefs.page.value && shared.collectUnsaved && shared.collectUnsaved().length) {
          const labels = shared.collectUnsaved().join('、');
          const restore = buildHash();
          shared.showConfirm({
            title: '未保存的更改',
            message: `${labels}有未保存的更改，离开将丢失。确定放弃并离开？`,
            type: 'warning',
          }).then((ok) => {
            if (ok) {
              if (shared.discardUnsaved) shared.discardUnsaved();
              applyHash(); // URL still points at the target — now proceed.
            } else if (window.location.hash !== restore) {
              window.location.hash = restore;
            }
          });
          return;
        }
        const set = (ref, v) => { if (ref && v && ref.value !== v) ref.value = v; };
        set(routeRefs.page, segs[0]);
        if (segs[0] === 'dashboard') set(routeRefs.dashTab, segs[1]);
        else if (segs[0] === 'config') set(routeRefs.cfgTab, segs[1]);
        else if (segs[0] === 'advanced') set(routeRefs.advTab, segs[1]);
        else if (segs[0] === 'waf') {
          set(routeRefs.wafTab, segs[1]);
          if (segs[1] === 'rules') set(routeRefs.wafRuleView, segs[2]);
          if (segs[1] === 'attacks') set(routeRefs.wafAttackView, segs[2]);
        } else if (segs[0] === 'kb') set(routeRefs.kbTab, segs[1]);
      };

      // Writer: any navigation change updates the URL (a history entry per
      // switch, so Back/Forward step through views). Our own write echoes back
      // as a hashchange, but applyHash() finds the refs already equal -> no-op,
      // which breaks the write/read loop without any flags.
      Vue.watch(
        [routeRefs.page, routeRefs.dashTab, routeRefs.cfgTab, routeRefs.advTab,
         routeRefs.wafTab, routeRefs.wafRuleView, routeRefs.wafAttackView, routeRefs.kbTab],
        () => {
          const h = buildHash();
          if (window.location.hash !== h) window.location.hash = h;
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