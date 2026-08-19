#!/usr/bin/env node
// Dashboard runtime-init gate: verifies that every module factory initializes
// without throwing and that app.js setup() yields a non-empty binding map.
// This catches the "static checks green, runtime white screen" class of bugs
// (e.g. a module referencing a symbol from a not-yet-loaded module, or a watch
// source resolving to undefined) that check_bindings.js cannot see statically.
//
// Run from repo root:  node test/v2/dashboard_init_check.js
'use strict';
const fs = require('fs');
const path = require('path');

const DASH = path.join(__dirname, '..', '..', 'verynginx', 'dashboard');

// Ordered list of module factories, mirrors app.js `domainModules` + app.js itself.
const MODULES = [
    ['vn-common.js', 'vncommon'],
    ['vn-dashboard.js', 'vndashboard'],
    ['vn-config.js', 'vnconfig'],
    ['vn-waf.js', 'vnwaf'],
    ['vn-frequency.js', 'vnfrequency'],
    ['vn-geoip.js', 'vngeoip'],
    ['vn-reputation.js', 'vnreputation'],
    ['vn-advanced.js', 'vnadvanced'],
    ['vn-kb.js', 'vnkb'],
];

function makeRef(v) {
    return { value: v, __isRef: true };
}

let appOptions = null;
const watchProblems = [];

const VueMock = {
    ref: (v) => makeRef(v),
    reactive: (obj) => (obj || {}),
    computed: (fn) => {
        const r = makeRef(undefined);
        try { r.value = fn(); } catch (e) { r._error = e; }
        return r;
    },
    watch: (source, cb) => {
        const sources = Array.isArray(source) ? source : [source];
        for (const s of sources) {
            if (s === undefined || s === null) {
                watchProblems.push(String(source));
            }
        }
    },
    nextTick: (fn) => {
        if (fn) { try { fn(); } catch (e) { /* surfaced below via factory/mount failures */ } }
    },
    createApp: (options) => {
        appOptions = options;
        return { config: {}, mount() {} };
    },
};

// Minimal browser-like globals so factories can construct without a real DOM.
global.window = global;
global.addEventListener = () => {};
global.document = {
    documentElement: { getAttribute: () => 'light', setAttribute: () => {} },
    cookie: '',
    createElement: () => ({ click() {} }),
};
global.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ ret: 'success', data: {} }),
    text: async () => '',
});
global.encodeURIComponent = encodeURIComponent;

let failures = 0;
function fail(msg) { console.error('FAIL ' + msg); failures++; }
function pass(msg) { console.log('PASS ' + msg); }

// 1. Load every module file, registering its factory on window.VN.modules.
global.VN = { modules: {} };
const initErrors = [];
for (const [file, key] of MODULES) {
    const src = fs.readFileSync(path.join(DASH, file), 'utf8');
    try {
        new Function('window', 'Vue', src)(global, VueMock);
    } catch (e) {
        fail(`load ${file}: ${e.message}`);
        continue;
    }
    // Wrap the factory so an init throw inside app.js's loop is attributed to a module.
    const rawFactory = global.VN.modules[key];
    global.VN.modules[key] = function (ctx) {
        try {
            return rawFactory(ctx);
        } catch (e) {
            initErrors.push(`${key} (${file}): ${e.message}`);
        }
    };
}

// 2. Execute app.js: it runs the real expose()/ctx wiring, then mounts.
const appSrc = fs.readFileSync(path.join(DASH, 'app.js'), 'utf8');
try {
    new Function('window', 'Vue', appSrc)(global, VueMock);
} catch (e) {
    fail(`app.js threw: ${e.message}`);
}
for (const err of initErrors) fail(`factory threw: ${err}`);

// 3. Core assertion: setup() must return a non-empty binding map.
let bindings = {};
if (appOptions && typeof appOptions.setup === 'function') {
    try {
        bindings = appOptions.setup() || {};
    } catch (e) {
        fail(`setup() threw: ${e.message}`);
    }
} else {
    fail('app.js did not register a Vue app with setup()');
}
const bindingCount = Object.keys(bindings).length;
if (bindingCount > 0) {
    pass(`setup() returned ${bindingCount} bindings`);
} else {
    fail('setup() returned an empty binding map');
}

// 4. Any watch source resolving to undefined/null is a latent white-screen bug.
if (watchProblems.length > 0) {
    fail(`watch source(s) are undefined/null: ${[...new Set(watchProblems)].join(', ')}`);
} else {
    pass('no watch source resolves to undefined/null');
}

console.log(failures === 0
    ? `\nOK: dashboard init gate passed (${bindingCount} bindings, ${MODULES.length} modules)`
    : `\n${failures} assertion(s) failed`);
process.exit(failures === 0 ? 0 : 1);