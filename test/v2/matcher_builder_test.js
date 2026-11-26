#!/usr/bin/env node
// Functional tests for the visual matcher builder.
// Loads vn-common.js with a minimal Vue/browser mock, then drives the builder
// functions registered via view()/ctx() to verify parse -> emit round-trips for
// the matcher shapes actually consumed by matcher/init.lua.
//
// Run: node test/v2/matcher_builder_test.js
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DASH = path.join(__dirname, '..', '..', 'verynginx', 'dashboard');
const src = fs.readFileSync(path.join(DASH, 'vn-common.js'), 'utf8');

let PASS = 0, FAIL = 0;
const ok = (m) => { PASS++; console.log('  [PASS] ' + m); };
const ko = (m) => { FAIL++; console.log('  [FAIL] ' + m); };

function makeRef(v) { return { value: v }; }

// Collect view()/ctx() exports from a script that calls window.VN.modules[...]
function loadCommon() {
    const exports = {};
    const sandbox = {
        console,
        Math,
        JSON,
        Date,
        setTimeout: () => {},
        clearTimeout: () => {},
        setInterval: () => {},
        clearInterval: () => {},
        Vue: {
            ref: (v) => makeRef(v),
            reactive: (o) => (o || {}),
            computed: (fn) => makeRef(fn()),
            watch: () => {},
            nextTick: (f) => { if (f) f(); },
        },
        window: { VN: { modules: {} }, addEventListener: () => {}, location: { hash: '' } },
        document: { hidden: false, addEventListener: () => {}, querySelector: () => null },
        localStorage: { getItem: () => null, setItem: () => {} },
        fetch: async () => ({ ok: false, status: 0, json: async () => ({}), text: async () => '' }),
        location: { hash: '' },
        navigator: { userAgent: '' },
        btoa: (s) => s,
        atob: (s) => s,
        TextEncoder: function () {},
        URLSearchParams: function () {},
        encodeURIComponent,
        decodeURIComponent,
    };
    sandbox.globalThis = sandbox;
    // ctx/view capture: register into exports. The module reads them from shared.
    const ctx = (name, value) => { exports[name] = value; };
    const view = (name, value) => { exports[name] = value; };
    sandbox.document.documentElement = { getAttribute: () => 'light', setAttribute: () => {} };
    vm.createContext(sandbox);
    vm.runInContext(src, sandbox, { filename: 'vn-common.js' });
    // Invoke the factory with our ctx/view; it registers everything.
    sandbox.window.VN.modules['vncommon']({ ctx, view });
    return exports;
}

function main() {
    console.log('== visual matcher builder ==');
    let e;
    try { e = loadCommon(); }
    catch (err) { ko('vn-common factory failed: ' + err.message); return finish(); }

    const mb = e.mb;
    if (!mb || typeof e.mbOpen !== 'function') { ko('builder exports missing'); return finish(); }
    ok('builder exports present (mb, mbOpen, mbApply, ...)');

    // Register a fake target editor
    let target = '{}';
    e.mbBindTarget('test', () => target, (v) => { target = v; });

    // 1) simple single condition round-trip
    target = JSON.stringify({ URI: { operator: '≈', value: '/admin' } });
    e.mbOpen('test');
    if (mb.logic === 'single' && mb.rows.length === 1 && mb.rows[0].field === 'URI'
        && mb.rows[0].value === '/admin') ok('single condition parsed into a row');
    else ko('single condition parse: ' + JSON.stringify(mb));
    e.mbApply();
    let parsed = JSON.parse(target);
    if (parsed.URI && parsed.URI.value === '/admin') ok('single condition emits original JSON shape');
    else ko('single condition emit: ' + target);

    // 2) named field (Args) round-trip with name_operator/name_value
    target = JSON.stringify({ Args: { name_operator: '=', name_value: 'id', operator: '≈', value: '\\d+' } });
    e.mbOpen('test');
    const row = mb.rows[0];
    if (row.field === 'Args' && row.nameVal === 'id' && row.nameOp === '=' && row.value === '\\d+')
        ok('Args name/value parsed');
    else ko('Args parse: ' + JSON.stringify(row));
    e.mbApply();
    parsed = JSON.parse(target);
    if (parsed.Args && parsed.Args.name_value === 'id' && parsed.Args.value === '\\d+')
        ok('Args name/value emitted');
    else ko('Args emit: ' + target);

    // 3) OR composite with two conditions
    target = JSON.stringify({ Composite: { operator: 'OR', conditions: [
        { URI: { operator: '≈', value: '/favicon.ico' } },
        { UserAgent: { operator: '≈', value: 'Go-http-client' } },
    ] } });
    e.mbOpen('test');
    if (mb.logic === 'OR' && mb.rows.length === 2) ok('OR composite parsed into 2 rows');
    else ko('OR parse: ' + JSON.stringify(mb));
    e.mbApply();
    parsed = JSON.parse(target);
    if (parsed.Composite && parsed.Composite.operator === 'OR' && parsed.Composite.conditions.length === 2)
        ok('OR composite emitted');
    else ko('OR emit: ' + target);

    // 4) operator '*' must not carry a value
    e.mbOpen('test');
    mb.logic = 'single';
    mb.rows = [{ field: 'Header', nameOp: '=', nameVal: 'X-Test', op: '*', value: '' }];
    e.mbApply();
    parsed = JSON.parse(target);
    if (parsed.Header && parsed.Header.operator === '*' && !('value' in parsed.Header))
        ok("'*' operator omits value field");
    else ko("'*' emit: " + target);

    // 5) nested composite is rejected (left to JSON mode) rather than mangled
    target = JSON.stringify({ Composite: { operator: 'AND', conditions: [
        { Composite: { operator: 'OR', conditions: [{ URI: { operator: '=', value: '/x' } }] } },
    ] } });
    e.mbOpen('test');
    if (mb.mode === 'json' && /嵌套/.test(mb.error)) ok('nested composite falls back to JSON mode with error');
    else ko('nested composite handling: mode=' + mb.mode + ' error=' + mb.error);

    // 6) invalid JSON input goes to JSON mode, not a throw
    target = 'this is not json';
    e.mbOpen('test');
    if (mb.mode === 'json') ok('invalid JSON opens in JSON mode');
    else ko('invalid JSON mode: ' + mb.mode);

    finish();
}

function finish() {
    console.log('');
    console.log('matcher builder tests: %d passed, %d failed', PASS, FAIL);
    process.exit(FAIL ? 1 : 0);
}

main();
