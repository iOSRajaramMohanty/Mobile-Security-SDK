#!/usr/bin/env node
/**
 * Build gate: disallow unpinned network primitives in the RN JS layer.
 *
 * Phase 4 strict pinning requirement:
 * - secureRequest/registerDevice must use native pinned HTTP (no `fetch` fallback).
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const srcDir = path.join(root, 'src');

const bad = [
  /\bfetch\s*\(/,
  /\bXMLHttpRequest\b/,
  /\baxios\b/,
];

const offenders = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const fp = path.join(dir, name);
    const st = statSync(fp);
    if (st.isDirectory()) walk(fp);
    else if (name.endsWith('.ts') || name.endsWith('.tsx')) {
      const t = readFileSync(fp, 'utf8');
      for (const re of bad) {
        if (re.test(t)) {
          offenders.push(`${path.relative(root, fp)} matches ${re}`);
          break;
        }
      }
    }
  }
}

walk(srcDir);

if (offenders.length) {
  console.error('Strict pinning violation: JS network primitive detected.');
  for (const o of offenders) console.error(`- ${o}`);
  process.exit(1);
}
process.exit(0);

