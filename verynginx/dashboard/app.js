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