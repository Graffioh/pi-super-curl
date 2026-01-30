#!/usr/bin/env bun
/**
 * Example post-processing script for pi-super-curl
 * 
 * This script is called by /scurl-log after logs are copied.
 * It receives the output directory as an argument.
 * 
 * Usage: bun process-output.js <output-dir>
 */

const fs = require('fs');
const path = require('path');

const outputDir = process.argv[2];

if (!outputDir) {
  console.error('Usage: bun process-output.js <output-dir>');
  process.exit(1);
}

console.log(`[INFO] Processing output in: ${outputDir}`);

// Rename log files
const renames = {
  'backend.txt': 'backend-logs.txt'
};

for (const [from, to] of Object.entries(renames)) {
  const fromPath = path.join(outputDir, from);
  const toPath = path.join(outputDir, to);
  if (fs.existsSync(fromPath)) {
    fs.renameSync(fromPath, toPath);
    console.log(`[INFO] Renamed ${from} -> ${to}`);
  }
}

// Create a simple info.txt
const timestamp = new Date().toISOString();
const info = `Request Log
===========

Captured: ${timestamp}
Directory: ${outputDir}

Files:
${fs.readdirSync(outputDir).map(f => `  - ${f}`).join('\n')}
`;

fs.writeFileSync(path.join(outputDir, 'info.txt'), info);
console.log('[INFO] Created info.txt');

console.log('[INFO] Processing complete');
