import pg from 'pg';

export type Db = {
  pool: pg.Pool;
  close: () => Promise<void>;
};

export function createDb(): Db {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is required');
  }
  const pool = new pg.Pool({ connectionString, max: Number(process.env.DB_POOL_MAX ?? 10) });
  return {
    pool,
    close: async () => {
      await pool.end();
    },
  };
}

