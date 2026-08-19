#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../../verynginx/dashboard/index.html');
const content = fs.readFileSync(file, 'utf8');

// Read all module files for expose() calls
const moduleFiles = [
    'vn-common.js',
    'vn-dashboard.js',
    'vn-config.js',
    'vn-waf.js',
    'vn-frequency.js',
    'vn-geoip.js',
    'vn-reputation.js',
    'vn-advanced.js',
    'vn-kb.js',
    'app.js',
];
let script = '';
for (const fname of moduleFiles) {
    const fpath = path.join(__dirname, '../../verynginx/dashboard', fname);
    if (fs.existsSync(fpath)) {
        script += fs.readFileSync(fpath, 'utf8') + '\n';
    } else {
        console.warn('WARN: Module file not found:', fname);
    }
}
if (!script.trim()) {
    console.error('ERROR: No module scripts found');
    process.exit(1);
}

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
  // New pattern: all exports are via expose() calls
  // Delegate to extractExposedBindings
  return extractExposedBindings(script);
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