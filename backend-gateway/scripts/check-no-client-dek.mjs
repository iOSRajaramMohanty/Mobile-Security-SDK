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
    else if (ent.isFile() && (p.endsWith('.ts') || p.endsWith('.js'))) {
      const txt = fs.readFileSync(p, 'utf8');
      if (txt.includes('_clientDek')) {
        // Allow only server-side defensive checks and secure forwarding logic.
        const allowed =
          p.endsWith(path.join('src', 'index.ts')) ||
          p.endsWith(path.join('src', 'forwarding.ts')) ||
          p.endsWith(path.join('src', 'secureEnvelope.ts'));
        if (!allowed) offenders.push(p);
      }
    }
  }
}

walk(srcDir);

if (offenders.length) {
  console.error('[CHECK] FAIL: _clientDek usage found in backend-gateway sources:');
  for (const f of offenders) console.error(`- ${f}`);
  process.exit(1);
}

console.log('[CHECK] PASS: no unexpected _clientDek usage in backend-gateway');

