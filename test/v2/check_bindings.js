#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../../verynginx/dashboard/index.html');
const content = fs.readFileSync(file, 'utf8');

const scriptMatches = [...content.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  if (scriptMatches.length < 2) {
    console.error('ERROR: Expected at least 2 <script> blocks, found', scriptMatches.length);
    process.exit(1);
  }
  // Use the LAST script block (the Vue app)
  const script = scriptMatches[scriptMatches.length - 1][1];

// Extract template from #app div
const lines = content.split('\n');
let inApp = false;
let depth = 0;
let templateLines = [];
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  if (!inApp) {
    if (line.includes('id="app"')) {
      inApp = true;
      depth = 1;
      templateLines.push(line);
    }
  } else {
    templateLines.push(line);
    const openCount = (line.match(/<div/g) || []).length;
    const closeCount = (line.match(/<\/div>/g) || []).length;
    depth += openCount - closeCount;
    if (depth <= 0) break;
  }
}
const template = templateLines.join('\n');

function extractReturnBindings(script) {
  // Find the setup() function body - look for "setup() {" 
  const setupIdx = script.indexOf('setup() {');
  if (setupIdx < 0) return new Set();
  
  // Find the matching closing brace for setup function
  let depth = 1;
  let i = setupIdx + 9; // after "setup() {"
  for (; i < script.length && depth > 0; i++) {
    if (script[i] === '{') depth++;
    else if (script[i] === '}') depth--;
  }
  const setupBody = script.substring(setupIdx + 9, i - 1);
  
  // Find all return statements in setup body, take the last one
  const returnMatches = [...setupBody.matchAll(/return\s*{([\s\S]*?)};/g)];
  if (returnMatches.length === 0) return new Set();
  const returnBody = returnMatches[returnMatches.length - 1][1];
  
  const bindings = new Set();
  const lines = returnBody.split('\n');
  for (const line of lines) {
    const trimmed = line.trim().replace(/,$/, '');
    if (!trimmed || trimmed.startsWith('//')) continue;
    const parts = trimmed.split(/\s+/);
    for (const part of parts) {
      const name = part.replace(/,$/, '').trim();
      if (name && !name.includes(':')) bindings.add(name);
    }
  }
  return bindings;
}

function extractTemplateBindings(template) {
  const bindings = new Set();
  const skipNames = new Set([
    'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Date', 'RegExp', 'Map', 'Set', 'Promise',
    'console', 'window', 'document', 'localStorage', 'sessionStorage', 'navigator', 'location', 'history',
    'i', 'k', 'idx', 'key', 'item', 'value', 'name', 'v', 'e', 'd', 'a', 'b', 'c', 'h', 'm',
    'action', 'group', 'category', 'count', 'code', 'data', 'errors', 'message', 'method', 'host', 'ip',
    'mode', 'limit', 'enabled', 'name', 'label', 'type', 'status', 'error', 'keys', 'list', 'map',
    'in', 'out', 'at', 'by', 'on', 'to', 'from', 'for', 'of', 'as', 'is', 'has', 'get', 'set', 'add', 'del',
    'formatTime', 'formatBytes', 'formatNumber', 'calcSuccess', 'successClass', 'summarizeRule', 'actionClass',
    'fmtTime', 'gradeStyle', 'formatKbTime', 'formatKbExpiry', 'formatAgo', 'formatNumber', 'categoryColor',
    'timelineBarHeight', 'sevClass', 'auditActionClass', 'kbTimelineActionClass', 'kbTimelineActionLabel',
    'kbEvidenceSummary', 'kbChecklist', 'kbReasonItems', 'wafDiffLines', 'hasTimelineData',
    'parsePrometheus', 'showToast', 'showConfirm', 'confirmModalOk', 'confirmModalCancel',
    'navigateTo', 'toggleTheme', 'loadStatus', 'loadConfig', 'loadData', 'loadOverview', 'loadDictUsage',
    'editMatcher', 'saveMatcher', 'deleteMatcher', 'commitConfig', 'saveRawConfig', 'loadStats',
    'ruleEditReset', 'ruleBuildRule', 'ruleOpenCreate', 'ruleOpenEdit', 'ruleEditModalChanged', 'ruleSave',
    'ruleDelete', 'ruleToggle', 'loadWafRules', 'loadWafStats', 'loadWafHistory', 'loadWafData',
    'loadWafAttackData', 'wafOpenCreate', 'wafOpenEdit', 'wafSaveRule', 'wafDeleteRule', 'wafToggleRule',
    'wafPage', 'wafRefreshAll', 'wafRollback', 'wafRunTest', 'loadWafHits', 'wafLoadMoreHits',
    'loadWafAnalytics', 'loadWafTimeline', 'loadTestHistory', 'clearTestHistory', 'openHitDetail',
    'addToWhitelist', 'viewIpHits', 'editRuleById', 'loadRecs', 'runRecAnalysis', 'applyRec', 'dismissRec',
    'openFreqRuleCreate', 'saveFreqRule', 'deleteFreqRule', 'previewFreqTemplate', 'applyFreqTemplate',
    'lookupGeoIP', 'saveGeoIPConfig', 'triggerGeoIPUpdate', 'loadFingerprints', 'openFpAdd',
    'toggleFp', 'deleteFp', 'loadPlugins', 'togglePlugin', 'exportConfig', 'importConfig', 'onImportFile',
    'loadTopPaths', 'loadRepData', 'repClear', 'repAddWhitelist', 'repRemoveWhitelist', 'repPersist',
    'repLookup', 'loadAudit', 'clearAuditFilters', 'setAuditSincePreset', 'loadKbTimeline', 'loadKbData',
    'loadKbEntries', 'loadKbCandidates', 'loadKbDashboard', 'loadKbBucketHistory', 'kbEntriesPagePrev',
    'kbCandidatesPagePrev', 'kbEntriesPageNext', 'kbCandidatesPageNext', 'kbOpenDetail', 'kbReloadList',
    'kbSaveSettings', 'kbMarkFormDirty', 'kbPromote', 'kbPromoteIp', 'kbClear', 'kbPause', 'kbFlushAuto',
    'kbReconcile', 'refreshConfig', 'openFreqRuleEdit', 'enableCcEnforceReady',
    'startStatusRefresh', 'startHealthRefresh', 'kbTrendFillEnforce', 'kbTrendFillObserve',
    'color', 'background', 'height', 'display', 'width', 'margin', 'padding', 'border', 'radius',
    'backgroundColor', 'fontSize', 'fontWeight', 'textAlign', 'lineHeight', 'cursor', 'pointer',
    'hover', 'focus', 'active', 'disabled', 'readonly', 'required', 'selected', 'checked', 'hidden',
    'visible', 'show', 'open', 'close', 'on', 'off', 'yes', 'no', 'true', 'false', 'null', 'undefined',
    'parseInt', 'parseFloat',
  ]);
  
  // Track v-for local variables
  const vforLocals = new Set();
  const vforPattern = /v-for\s*=\s*["']\s*\(?\s*([a-zA-Z_$][\w$]*)\s*(?:,\s*([a-zA-Z_$][\w$]*)\s*)?\)?\s+in\s+/g;
  let vforMatch;
  while ((vforMatch = vforPattern.exec(template)) !== null) {
    if (vforMatch[1]) vforLocals.add(vforMatch[1]);
    if (vforMatch[2]) vforLocals.add(vforMatch[2]);
  }
  
  const patterns = [
    /v-if\s*=\s*["']([^"']+)["']/g,
    /v-show\s*=\s*["']([^"']+)["']/g,
    /@click\s*=\s*["']([^"']+)["']/g,
    /@input\s*=\s*["']([^"']+)["']/g,
    /@change\s*=\s*["']([^"']+)["']/g,
    /@submit\s*=\s*["']([^"']+)["']/g,
    /@keyup\.\w+\s*=\s*["']([^"']+)["']/g,
    /:disabled\s*=\s*["']([^"']+)["']/g,
    /:class\s*=\s*["']([^"']+)["']/g,
    /:style\s*=\s*["']([^"']+)["']/g,
    /:value\s*=\s*["']([^"']+)["']/g,
    /:key\s*=\s*["']([^"']+)["']/g,
    /v-model\s*=\s*["']([^"']+)["']/g,
    /\{\{\s*([^}\s]+)\s*\}\}/g,
    /\{\{\s*([a-zA-Z_$][\w$.]*)\s*\}\}/g,
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(template)) !== null) {
      const expr = match[1].trim();
      // Only check the FIRST identifier in the expression (root binding)
      const firstToken = expr.match(/^[a-zA-Z_$][\w$]*/);
      if (firstToken) {
        const base = firstToken[0];
        if (!/^\d+$/.test(base) && !skipNames.has(base) && !vforLocals.has(base)) {
          bindings.add(base);
        }
      }
    }
  }
  return bindings;
}

function extractExposedBindings(script) {
  const bindings = new Set();
  const exposePattern = /expose\(['"]([^'"]+)['"]/g;
  let match;
  while ((match = exposePattern.exec(script)) !== null) {
    bindings.add(match[1]);
  }
  return bindings;
}

const returnBindings = extractReturnBindings(script);
const templateBindings = extractTemplateBindings(template);
const exposedBindings = extractExposedBindings(script);

const allExported = new Set([...returnBindings, ...exposedBindings]);

const missingInReturn = [...templateBindings].filter(b => !allExported.has(b)).sort();
const unusedInReturn = [...allExported].filter(b => !templateBindings.has(b)).sort();

let hasError = false;
if (missingInReturn.length > 0) {
  console.error('ERROR: Used in template but NOT exported in return/expose:');
  for (const name of missingInReturn) console.error('  -', name);
  hasError = true;
}
if (unusedInReturn.length > 0) {
  console.warn('WARN: Exported but NOT used in template:');
  for (const name of unusedInReturn) console.warn('  -', name);
}
if (!hasError) {
  console.log('OK: All template bindings are exported');
  console.log(`  Template bindings: ${templateBindings.size}`);
  console.log(`  Exported bindings: ${allExported.size}`);
  console.log(`  Unused exports: ${unusedInReturn.length}`);
}
process.exit(hasError ? 1 : 0);