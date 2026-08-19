#!/usr/bin/env node
// Shared dashboard binding analysis: authoritative render-scope set.
//
// The #app in-DOM template is the single source of truth for what setup() must
// return. This module extracts those bindings precisely (scope-aware v-for
// locals, object-literal keys, member properties, template refs, v-model
// modifiers) and compares against the view() exports in the module files.
//
// Both check_bindings.js and dashboard_init_check.js consume this.
'use strict';
const fs = require('fs');
const path = require('path');

const DASH = path.join(__dirname, '..', '..', 'verynginx', 'dashboard');

const MODULE_FILES = [
    'vn-common.js', 'vn-dashboard.js', 'vn-config.js', 'vn-waf.js', 'vn-frequency.js',
    'vn-geoip.js', 'vn-reputation.js', 'vn-advanced.js', 'vn-kb.js', 'app.js',
];

const GLOBALS = new Set([
    'Math', 'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Date', 'RegExp',
    'Promise', 'Set', 'Map', 'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURIComponent',
    'decodeURIComponent', 'Infinity', 'NaN', 'undefined', 'typeof', 'new', 'true', 'false', 'null',
]);

const VOID_TAGS = new Set(['br', 'img', 'input', 'hr', 'meta', 'link', 'source', 'wbr',
    'col', 'area', 'base', 'embed', 'param', 'track']);

// ---- #app template extraction ----
function extractAppTemplate(indexHtml) {
    const lines = indexHtml.split('\n');
    let inApp = false, depth = 0, out = [];
    for (const line of lines) {
        if (!inApp) {
            if (line.includes('id="app"')) { inApp = true; depth = 1; out.push(line); }
            continue;
        }
        out.push(line);
        depth += (line.match(/<div/g) || []).length - (line.match(/<\/div>/g) || []).length;
        if (depth <= 0) break;
    }
    return out.join('\n');
}

// ---- expression tokenizer: binding identifiers only ----
function exprBindings(expr) {
    const ids = new Set();
    const stack = [];
    let buf = '';
    let prevCode = -1;
    let nextIsProperty = false;
    let isProperty = false;
    const n = expr.length;
    const flush = (nextCode) => {
        if (buf) {
            const top = stack[stack.length - 1];
            const isObjectKey = top === '{' &&
                (prevCode === 123 || prevCode === 44 || prevCode === 58) &&
                nextCode === 58;
            if (!isObjectKey && !isProperty && !buf.startsWith('$') && !/^\d/.test(buf) && !GLOBALS.has(buf)) {
                ids.add(buf);
            }
            buf = '';
        }
        isProperty = false;
    };
    let i = 0;
    for (; i < n; i++) {
        const c = expr[i];
        const cc = c.charCodeAt(0);
        if (c === "'" || c === '"') {
            flush(0);
            const quote = c;
            i++;
            while (i < n && expr[i] !== quote) { if (expr[i] === '\\') i++; i++; }
            continue;
        }
        if (/[A-Za-z0-9_$]/.test(c)) {
            if (!buf) isProperty = nextIsProperty;
            buf += c;
            continue;
        }
        flush(cc);
        nextIsProperty = (c === '.');
        if (c === '(' || c === '[' || c === '{') stack.push(c);
        else if (c === ')' || c === ']' || c === '}') stack.pop();
        if (!/\s/.test(c)) prevCode = cc;
    }
    flush(0);
    return ids;
}

// ---- v-for locals declared on a tag ----
function tagVforLocals(attrs) {
    const locals = new Set();
    const m = attrs.match(/v-for\s*=\s*(?:"([^"]*)"|'([^']*)')/);
    if (!m) return locals;
    const value = m[1] !== undefined ? m[1] : m[2];
    const decl = value.split(/\s+in\s+/)[0].replace(/^\(|\)$/g, '').trim();
    for (const part of decl.split(',')) {
        const p = part.trim();
        if (/^[\w$]+$/.test(p)) locals.add(p);
    }
    return locals;
}

// ---- bound attribute expressions inside a tag ----
function attrExpressions(attrs, cb) {
    const re = /(?:@[\w.$]+|:[A-Za-z_-][\w.-]*|v-if|v-show|v-model(?:\.\w+)*|v-html|v-else-if|v-cloak)\s*=\s*(["'])([\s\S]*?)\1/g;
    let m;
    while ((m = re.exec(attrs)) !== null) cb(m[2]);
    const vfor = attrs.match(/v-for\s*=\s*(?:["']([^"']*)["'])/);
    if (vfor) {
        const rhs = vfor[1].split(/\s+in\s+/)[1];
        if (rhs) cb(rhs);
    }
    const refm = attrs.match(/\bref\s*=\s*["']([\w$]+)["']/);
    if (refm) cb(refm[1]);
}

// ---- authoritative template bindings (single pass, scope-aware) ----
function extractTemplateBindings(template) {
    const bindings = new Set();
    const scopeStack = [];
    const activeLocals = () => {
        const s = new Set();
        for (const sc of scopeStack) for (const l of sc.locals) s.add(l);
        return s;
    };
    const consider = (expr, locals) => {
        for (const id of exprBindings(expr)) if (!locals.has(id)) bindings.add(id);
    };
    const combined = /<(\/?)([A-Za-z][\w-]*)((?:"[^"]*"|'[^']*'|[^"'>])*)>|\{\{([\s\S]*?)\}\}/g;
    let m;
    while ((m = combined.exec(template)) !== null) {
        if (m[1] !== undefined) {
            const closing = m[1] === '/';
            const tag = (m[2] || '').toLowerCase();
            const attrs = m[3] || '';
            if (closing) {
                if (scopeStack.length) scopeStack.pop();
                continue;
            }
            const selfClosing = /\/\s*$/.test(attrs);
            const voidTag = VOID_TAGS.has(tag);
            const own = tagVforLocals(attrs);
            const locals = activeLocals();
            for (const l of own) locals.add(l);
            attrExpressions(attrs, (expr) => consider(expr, locals));
            if (!voidTag && !selfClosing) scopeStack.push({ locals: own });
        } else {
            consider(m[4], activeLocals());
        }
    }
    return bindings;
}

// ---- view() exports across module files ----
function extractViewExports(script) {
    const names = new Set();
    const re = /view\(['"]([^'"]+)['"]/g;
    let m;
    while ((m = re.exec(script)) !== null) names.add(m[1]);
    return names;
}

function readModules() {
    let script = '';
    for (const f of MODULE_FILES) {
        const p = path.join(DASH, f);
        if (fs.existsSync(p)) script += fs.readFileSync(p, 'utf8') + '\n';
    }
    return script;
}

function compute() {
    const indexHtml = fs.readFileSync(path.join(DASH, 'index.html'), 'utf8');
    const template = extractAppTemplate(indexHtml);
    const templateBindings = extractTemplateBindings(template);
    const viewExports = extractViewExports(readModules());
    return { templateBindings, viewExports };
}

module.exports = {
    extractAppTemplate,
    extractTemplateBindings,
    extractViewExports,
    readModules,
    compute,
    DASH,
    MODULE_FILES,
};

// CLI: print the authoritative template-binding set (used by the converter).
if (require.main === module) {
    const { templateBindings } = compute();
    console.log([...templateBindings].sort().join('\n'));
}