#!/usr/bin/env node
/**
 * Simple migrations runner for backend-gateway.
 *
 * Usage:
 *   DATABASE_URL=... node scripts/migrate.mjs
 */

import pg from 'pg';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const migrationsDir = path.resolve(process.cwd(), 'migrations');
const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}

const pool = new pg.Pool({ connectionString, max: 2 });

async function main() {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
      id text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    );`,
  );

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const id = file;
    const already = await pool.query(`SELECT 1 FROM schema_migrations WHERE id=$1`, [id]);
    if (already.rowCount) continue;

    const sql = readFileSync(path.join(migrationsDir, file), 'utf8');
    console.log(`Applying ${id}...`);
    await pool.query('BEGIN');
    try {
      await pool.query(sql);
      await pool.query(`INSERT INTO schema_migrations (id) VALUES ($1)`, [id]);
      await pool.query('COMMIT');
    } catch (e) {
      await pool.query('ROLLBACK');
      throw e;
    }
  }
}

main()
  .then(async () => {
    console.log('Migrations complete');
    await pool.end();
  })
  .catch(async (e) => {
    console.error(e);
    await pool.end();
    process.exit(1);
  });

