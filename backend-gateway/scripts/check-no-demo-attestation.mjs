#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const srcDir = path.join(root, 'src');

const offenders = [];
function walk(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(p);
    else if (ent.isFile() && p.endsWith('.ts')) {
      const txt = fs.readFileSync(p, 'utf8');
      // Match only direct imports of ./attestation (not ./attestationService, etc).
      if (/(from\s+['"]\.\/attestation(\.js|\.ts)?['"]|import\s+['"]\.\/attestation(\.js|\.ts)?['"])/.test(txt)) {
        offenders.push(p);
      }
    }
  }
}
walk(srcDir);

if (offenders.length) {
  console.error('[CHECK] FAIL: demo attestation import found:');
  for (const f of offenders) console.error(`- ${f}`);
  process.exit(1);
}
console.log('[CHECK] PASS: no demo attestation imports');

