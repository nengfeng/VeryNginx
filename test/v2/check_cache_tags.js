#!/usr/bin/env node
// Dashboard cache-tag gate: every local asset URL in index.html must carry a
// ?v= tag whose base is the current VERSION. The base was left at 2.2.1 across
// the v2.3.0 release, so browsers/intermediaries could keep an old JS file
// after an upgrade — the "new HTML + old JS" class of bug the comment next to
// the script tags warns about.
//
// This gate cannot know whether a file's content changed (that needs git
// history); it enforces the release half of the rule. Bump the per-file
// counter whenever the asset changes.
//
// Run from repo root:  node test/v2/check_cache_tags.js
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const version = fs.readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim().replace(/^v/i, '');
if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error(`FAIL: VERSION is not a plain x.y.z release: ${JSON.stringify(version)}`);
    process.exit(1);
}

const html = fs.readFileSync(path.join(ROOT, 'verynginx', 'dashboard', 'index.html'), 'utf8');
// Every local dashboard asset, whether or not it is versioned. Checking only
// URLs that already have ?v= would silently pass a newly added, unversioned
// script.
const urls = [...html.matchAll(/(?:src|href)="([^"]+)"/g)]
    .map((m) => m[1])
    .filter((u) => u.startsWith('/verynginx/static/'));
if (urls.length === 0) {
    console.error('FAIL: no local dashboard asset URLs found in index.html');
    process.exit(1);
}

const bad = [];
for (const url of urls) {
    const m = url.match(/[?&]v=([^&#]+)/);
    if (!m) {
        bad.push(`${url} has no ?v= cache tag`);
    } else if (!m[1].startsWith(`${version}-`)) {
        bad.push(`${url} has ?v=${m[1]}, expected ${version}-<n> (VERSION is ${version})`);
    }
}
if (bad.length) {
    for (const line of bad) console.error(`FAIL: ${line}`);
    process.exit(1);
}

console.log(`OK: ${urls.length} local asset URLs carry ?v=${version}-* (VERSION ${version})`);
