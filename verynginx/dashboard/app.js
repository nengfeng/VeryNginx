// app.js - Main entry point for VeryNginx Dashboard
// IIFE pattern for classic script loading

(function() {
    // Namespace for module factories
    window.VN = window.VN || {};
    window.VN.modules = window.VN.modules || {};

    const exports = new Map();
    // expose() populates BOTH the Vue render scope AND ctx (shared registry).
    // Any module can therefore read anything exposed by an earlier module via ctx.
    function expose(name, value) {
        exports.set(name, value);
        ctx[name] = value;
    }

    // Shared context - populated live by expose() as modules initialize.
    // Modules running later can destructure anything exposed earlier.
    const ctx = { expose };

    // Initialize modules in dependency order:
    // 1. Common (shared state + core utilities)
    // 2. Domain modules (may read earlier modules' exports from ctx)
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
            window.VN.modules[name](ctx);
        }
    }

    // Mount Vue app
    const app = Vue.createApp({
        setup() {
            return Object.fromEntries(exports);
        }
    });

    app.mount('#app');

})();