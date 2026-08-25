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
const computedErrors = [];

const VueMock = {
    ref: (v) => makeRef(v),
    reactive: (obj) => (obj || {}),
    computed: (fn) => {
        const r = makeRef(undefined);
        try { r.value = fn(); } catch (e) { r._error = e; computedErrors.push(String(e.message || e)); }
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

// 5. No computed may throw at init (a throwing computed = silent white screen
//    in the runtime-only Vue build once the page actually renders).
if (computedErrors.length > 0) {
    fail(`computed(s) threw at init: ${[...new Set(computedErrors)].join(', ')}`);
} else {
    pass('no computed throws at init');
}

// 6. No duplicate view()/ctx() exports (silent last-wins overwrite).
const dups = global.VN._dups || [];
if (dups.length > 0) {
    fail(`duplicate exports: ${[...new Set(dups)].join(', ')}`);
} else {
    pass('no duplicate view()/ctx() exports');
}

// 7. ctx helpers must be destructured from `shared` before use. Factories
//    run at init but loaders run LATER — a bare `asList(...)` inside a
//    non-destructured module only explodes on first data load (field bug:
//    WAF rules list died with "asList is not defined").
{
    const commonSrc = fs.readFileSync(path.join(DASH, 'vn-common.js'), 'utf8');
    const ctxNames = [...commonSrc.matchAll(/\bctx\('([A-Za-z_$][\w$]*)'/g)].map(m => m[1]);
    const missing = [];
    for (const f of MODULE_FILES) {
        if (f === 'vn-common.js') continue; // defines them
        const src = fs.readFileSync(path.join(DASH, f), 'utf8');
        // strip comments so helper names in prose don't count as usage
        const code = src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
        const dm = code.match(/const\s*\{([^}]*)\}\s*=\s*shared/);
        const destructured = new Set(
            dm ? dm[1].split(',').map(s => s.trim().split(':')[0].trim()).filter(Boolean) : []
        );
        for (const name of ctxNames) {
            const defRe = new RegExp(`(function\\s+${name}\\s*\\(|const\\s+${name}\\s*=)`);
            const useRe = new RegExp(`(?<![\\w$.])${name}\\s*\\(`, 'g');
            const uses = [...code.matchAll(useRe)]
                .filter(m => !defRe.test(code.slice(Math.max(0, m.index - 200), m.index)));
            if (uses.length > 0 && !destructured.has(name)) {
                missing.push(`${f}: ${name}(...) used but not in shared-destructure`);
            }
        }
    }
    if (missing.length > 0) fail(`ctx helper(s) not destructured: ${missing.join('; ')}`);
    else pass('all ctx helpers destructured where used');
}

// 8. Every array-typed API assignment must pass through asList(). A single
//    null hole from the backend crashes the v-for render subtree (field bug
//    class: "Cannot read properties of null (reading 'id')"). Object-shaped
//    payloads are allowed ONLY when their array sub-keys are sanitized in a
//    nearby statement (within 400 chars after the assignment).
{
    // Tier 1 — non-array payloads (objects / scalars): no asList required.
    const ALLOW_PLAIN = new Set([
        'versionInfo',      // {version, commit}
        'healthData',       // map name -> node-health (keyed lookups only)
        'geoipStatus',      // status object
        'geoipStats',       // rebuilt locally via Object.entries().map()
        'kbStatus',         // status object
        'kbEntriesNext',    // pagination cursor (string)
        'kbCandidatesNext', // pagination cursor (string)
        'repLookupResult',  // single lookup result object
        'wafCategories',    // object map, no direct item v-for
    ]);
    // Tier 2 — object payloads whose ARRAY sub-keys must be sanitized within
    // 8 lines after the assignment.
    const ALLOW_WINDOW = new Set([
        'cfg',             // rule groups normalized right below the assign
        'wafTimeline',     // .buckets
        'wafTestResults',  // .results
        'kbDiff',          // missing_in_kernel / orphan_in_kernel
    ]);
    const bad = [];
    for (const f of MODULE_FILES) {
        const src = fs.readFileSync(path.join(DASH, f), 'utf8');
        const lines = src.split('\n');
        lines.forEach((line, i) => {
            if (!/\.value\s*=\s*[^;\n]*\b(d\.data|[a-zA-Z]+Res\.data|d\.data\.[a-zA-Z]+)\b/.test(line)) return;
            if (/asList\(/.test(line)) return;
            const vm = line.match(/([a-zA-Z][\w]*)\.value\s*=/);
            const varName = vm ? vm[1] : '';
            if (ALLOW_PLAIN.has(varName)) return;
            if (ALLOW_WINDOW.has(varName)) {
                const window = lines.slice(i, i + 8).join('\n');
                if (/asList\(/.test(window)) return;
                bad.push(`${f}:${i + 1} ${varName}.value = ...data... but array sub-keys not asList-ed nearby`);
                return;
            }
            bad.push(`${f}:${i + 1} ${varName}.value = ...data... without asList`);
        });
    }
    if (bad.length > 0) fail(`unsanitized list assignments: ${bad.join('; ')}`);
    else pass('all data assignments sanitized via asList');
}

console.log(failures === 0
    ? `\nOK: dashboard init gate passed (${setupBindings.size} view bindings, ${MODULE_FILES.length - 1} modules)`
    : `\n${failures} assertion(s) failed`);
process.exit(failures === 0 ? 0 : 1);