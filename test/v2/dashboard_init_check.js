#!/usr/bin/env node
// Dashboard runtime-init gate: verifies that every module factory initializes
// without throwing, that app.js setup() returns EXACTLY the template's render
// scope (the authoritative view() set), and that no duplicate view/shared
// exports were registered. Catches the "static checks green, runtime white
// screen" class of bugs that template-vs-export analysis alone cannot see.
//
// Run from repo root:  node test/v2/dashboard_init_check.js
'use strict';
const fs = require('fs');
const path = require('path');
const { DASH, MODULE_FILES, compute } = require(path.join(__dirname, 'dashboard_bindings.js'));

// Authoritative render-scope bindings from the template.
const { templateBindings, viewExports } = compute();

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
    watch: (source) => {
        const sources = Array.isArray(source) ? source : [source];
        for (const s of sources) {
            if (s === undefined || s === null) {
                watchProblems.push(String(source));
            }
        }
    },
    nextTick: (fn) => { if (fn) { try { fn(); } catch (e) {} } },
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
//    (app.js is executed separately in step 2 - it runs the factories.)
global.VN = { modules: {}, _dups: [] };
const initErrors = [];
const FACTORY_FILES = MODULE_FILES.filter((f) => f !== 'app.js');
for (const file of FACTORY_FILES) {
    const src = fs.readFileSync(path.join(DASH, file), 'utf8');
    try {
        new Function('window', 'Vue', src)(global, VueMock);
    } catch (e) {
        fail(`load ${file}: ${e.message}`);
        continue;
    }
    const key = 'vn' + file.replace(/^vn-/, '').replace(/\.js$/, '');
    const rawFactory = global.VN.modules[key];
    if (!rawFactory) { fail(`no factory registered for ${file} (key ${key})`); continue; }
    global.VN.modules[key] = function (shared) {
        try { return rawFactory(shared); } catch (e) { initErrors.push(`${file}: ${e.message}`); }
    };
}

// 2. Execute app.js: it runs the real ctx()/view() wiring, then mounts.
try {
    new Function('window', 'Vue', fs.readFileSync(path.join(DASH, 'app.js'), 'utf8'))(global, VueMock);
} catch (e) {
    fail(`app.js threw: ${e.message}`);
}
for (const err of initErrors) fail(`factory threw: ${err}`);

// 3. setup() must return EXACTLY the template's render scope.
const setupBindings = appOptions && typeof appOptions.setup === 'function'
    ? new Set(Object.keys(((() => { try { return appOptions.setup() || {}; } catch (e) { fail(`setup() threw: ${e.message}`); return {}; } })())))
    : new Set();
if (!appOptions || typeof appOptions.setup !== 'function') {
    fail('app.js did not register a Vue app with setup()');
} else if (setupBindings.size === 0) {
    fail('setup() returned an empty binding map');
} else {
    pass(`setup() returned ${setupBindings.size} bindings`);
}

const missingSetup = [...templateBindings].filter((b) => !setupBindings.has(b));
const extraSetup = [...setupBindings].filter((b) => !templateBindings.has(b));
if (missingSetup.length) {
    fail(`setup() missing template bindings: ${missingSetup.join(', ')}`);
} else {
    pass(`setup() covers all ${templateBindings.size} template bindings`);
}
if (extraSetup.length) {
    fail(`setup() exposes non-template bindings (dead): ${extraSetup.join(', ')}`);
} else {
    pass('setup() exposes no dead bindings');
}

// 4. No watch source may resolve to undefined/null (factory-time destructure break).
if (watchProblems.length > 0) {
    fail(`watch source(s) are undefined/null: ${[...new Set(watchProblems)].join(', ')}`);
} else {
    pass('no watch source resolves to undefined/null');
}

// 5. No duplicate view()/ctx() exports (silent last-wins overwrite).
const dups = global.VN._dups || [];
if (dups.length > 0) {
    fail(`duplicate exports: ${[...new Set(dups)].join(', ')}`);
} else {
    pass('no duplicate view()/ctx() exports');
}

console.log(failures === 0
    ? `\nOK: dashboard init gate passed (${setupBindings.size} view bindings, ${MODULE_FILES.length - 1} modules)`
    : `\n${failures} assertion(s) failed`);
process.exit(failures === 0 ? 0 : 1);