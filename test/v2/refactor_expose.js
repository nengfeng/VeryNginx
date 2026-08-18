#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../../verynginx/dashboard/index.html');
const content = fs.readFileSync(file, 'utf8');

const scriptMatches = [...content.matchAll(/<script>([\s\S]*?)<\/script>/g)];
const script = scriptMatches[scriptMatches.length - 1][1];

// Find setup function bounds
const setupIdx = script.indexOf('setup() {');
if (setupIdx < 0) throw new Error('setup() not found');

let depth = 1;
let i = setupIdx + 9;
for (; i < script.length && depth > 0; i++) {
  if (script[i] === '{') depth++;
  else if (script[i] === '}') depth--;
}
const setupBodyStart = setupIdx + 9;
const setupBodyEnd = setupIdx + 9 + (i - (setupIdx + 9) - 1);
const setupBody = script.substring(setupBodyStart, setupBodyEnd);

// Find the last return statement in setup body (ORIGINAL, before modifications)
  const returnMatches = [...setupBody.matchAll(/return\s*{([\s\S]*?)};/g)];
  const lastReturnMatch = returnMatches[returnMatches.length - 1];
  const returnStartInSetup = lastReturnMatch.index;
  const returnEndInSetup = lastReturnMatch.index + lastReturnMatch[0].length;
  const returnBody = lastReturnMatch[1];

  console.log('Setup body length:', setupBody.length);
  console.log('Return match at:', returnStartInSetup, 'to', returnEndInSetup);
  console.log('Return body length:', returnBody.length);

  // Parse return bindings to know what's exported
  const returnBindings = new Set();
  const lines = returnBody.split('\n');
  for (const line of lines) {
    const trimmed = line.trim().replace(/,$/, '');
    if (!trimmed || trimmed.startsWith('//')) continue;
    const parts = trimmed.split(/\s+/);
    for (const part of parts) {
      const name = part.replace(/,$/, '').trim();
      if (name && !name.includes(':')) returnBindings.add(name);
    }
  }
  console.log('Return bindings:', returnBindings.size);

  // Now we need to transform the setup body:
  // 1. Add exports Map and expose function at the beginning
  // 2. Add expose() calls after each binding declaration
  // 3. Replace the return statement

  let newSetupBody = setupBody;

// 1. Add exports and expose at the beginning (after "setup() {\n")
  const insertPos = newSetupBody.indexOf('\n') + 1; // after first newline
  const exposeCode = `    const exports = new Map();
    function expose(name, value) { exports.set(name, value); }
    // Expose module-level store for template access
    expose('store', store);
`;
newSetupBody = newSetupBody.slice(0, insertPos) + exposeCode + newSetupBody.slice(insertPos);

// 2. Add expose() calls after each binding declaration
// We need to find all declarations and add expose after them
// This is complex because we need to handle multi-line declarations

// Strategy: Parse line by line and track declarations
  const newSetupLines = newSetupBody.split('\n');
  const outputLines = [];

  // Track multi-line declarations with brace counting
  let pendingExpose = null;
  let braceDepth = 0;
  let pendingExposeFirstLine = true;

  for (let i = 0; i < newSetupLines.length; i++) {
    const line = newSetupLines[i];
    
    // Count braces in this line
    const openBraces = (line.match(/{/g) || []).length;
    const closeBraces = (line.match(/}/g) || []).length;
    
    // Check for declarations BEFORE updating brace depth
    const declMatch = line.match(/(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:ref|reactive|computed)\s*\(/);
    const funcMatch = line.match(/(?:async\s+)?function\s+([a-zA-Z_$][\w$]*)\s*\(/);
    
    if (declMatch) {
      const name = declMatch[1];
      if (openBraces > closeBraces) {
        // Multi-line declaration starts
        pendingExpose = { name, indent: line.match(/^(\s*)/)[1] };
        braceDepth = openBraces - closeBraces;
        pendingExposeFirstLine = true;
      } else if (returnBindings.has(name)) {
        // Single-line declaration
        outputLines.push(line);
        const indent = line.match(/^(\s*)/)[1];
        outputLines.push(`${indent}    expose('${name}', ${name});`);
        continue;
      } else {
        outputLines.push(line);
        continue;
      }
    } else if (funcMatch) {
      const name = funcMatch[1];
      if (returnBindings.has(name)) {
        outputLines.push(line);
        const indent = line.match(/^(\s*)/)[1];
        outputLines.push(`${indent}    expose('${name}', ${name});`);
        continue;
      } else {
        outputLines.push(line);
        continue;
      }
    }
    
    // For lines that are part of a multi-line declaration (or regular lines)
    outputLines.push(line);
    
    // Update brace depth for pending expose AFTER pushing line
    if (pendingExpose) {
      if (pendingExposeFirstLine) {
        // First line already counted in braceDepth initialization
        pendingExposeFirstLine = false;
      } else {
        braceDepth += openBraces - closeBraces;
      }
      if (braceDepth <= 0 && returnBindings.has(pendingExpose.name)) {
        // Declaration ended, add expose
        outputLines.push(`${pendingExpose.indent}    expose('${pendingExpose.name}', ${pendingExpose.name});`);
        pendingExpose = null;
        braceDepth = 0;
        pendingExposeFirstLine = true;
      }
    }
  }

// 3. Replace the LAST return statement (the main one at end of setup)
  let modifiedBody = outputLines.join('\n');

  // Find all return statements and replace the last one
  const returnPattern2 = /return\s*{[\s\S]*?};/g;
  const returnMatches2 = [...modifiedBody.matchAll(returnPattern2)];
  if (returnMatches2.length > 0) {
    const lastMatch = returnMatches2[returnMatches2.length - 1];
    const before = modifiedBody.substring(0, lastMatch.index);
    const after = modifiedBody.substring(lastMatch.index + lastMatch[0].length);
    // Replace with return statement + closing brace for setup function
    modifiedBody = before + '    return Object.fromEntries(exports);\n  }' + after;
  }

console.log('Modified body length:', modifiedBody.length);

// Now reconstruct the full script
const beforeSetup = script.substring(0, setupBodyStart);
const afterSetup = script.substring(setupBodyEnd + 1);
const newScript = beforeSetup + modifiedBody + afterSetup;

// Verify the new script is valid
  console.log('New script setup start:', JSON.stringify(newScript.substring(newScript.indexOf('setup() {'), newScript.indexOf('setup() {') + 150)));
  try {
    new Function(newScript);
    console.log('JS syntax OK');
  } catch (e) {
    console.error('JS syntax error:', e.message);
    // Write to temp for debugging
    fs.writeFileSync('/tmp/debug_newScript.js', newScript);
    console.log('Written to /tmp/debug_newScript.js');
    process.exit(1);
  }

// Write back to the HTML
const newContent = content.replace(script, newScript);
fs.writeFileSync(file, newContent);
console.log('File updated successfully');