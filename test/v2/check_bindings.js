#!/usr/bin/env node
// Dashboard binding gate: the template is the single source of truth.
// Asserts that every render-scope binding the #app template references is
// exposed via view() in the modules, and that no view() export is dead.
// (Internal cross-module values registered via ctx() are intentionally NOT
// part of the render scope and are out of scope here.)
//
// Run from repo root:  node test/v2/check_bindings.js
'use strict';
const path = require('path');
const { compute } = require(path.join(__dirname, 'dashboard_bindings.js'));

const { templateBindings, viewExports } = compute();

const missing = [...templateBindings].filter((b) => !viewExports.has(b)).sort();
const dead = [...viewExports].filter((b) => !templateBindings.has(b)).sort();

let hasError = false;
if (missing.length > 0) {
    console.error('ERROR: Used in template but NOT exposed via view():');
    for (const name of missing) console.error('  -', name);
    hasError = true;
}
if (dead.length > 0) {
    console.error('ERROR: view() export not referenced by template (dead):');
    for (const name of dead) console.error('  -', name);
    hasError = true;
}

if (!hasError) {
    console.log('OK: template bindings == view() exports');
    console.log(`  Template bindings (view): ${templateBindings.size}`);
}
process.exit(hasError ? 1 : 0);