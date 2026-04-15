import type { RedisClientType } from 'redis';

/** Returns true if nonce was accepted (first use), false on replay. */
export interface NonceStore {
  acceptOnce(scope: string, nonce: string, ttlMs: number): Promise<boolean>;
}

/**
 * TTL-based in-memory store with pruning. Suitable for single-instance dev/small deploys.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();

  async acceptOnce(scope: string, nonce: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    this.prune(now);
    const k = `${scope}:${nonce}`;
    if (this.seen.has(k)) return false;
    this.seen.set(k, now + ttlMs);
    return true;
  }

  private prune(now: number): void {
    for (const [n, exp] of this.seen) {
      if (exp < now) this.seen.delete(n);
    }
  }
}

export class RedisNonceStore implements NonceStore {
  constructor(
    private readonly client: RedisClientType,
    private readonly keyPrefix: string,
  ) {}

  async acceptOnce(scope: string, nonce: string, ttlMs: number): Promise<boolean> {
    const key = `${this.keyPrefix}${scope}:${nonce}`;
    const sec = Math.max(1, Math.ceil(ttlMs / 1000));
    const result = await this.client.set(key, '1', { NX: true, EX: sec });
    return result !== null;
  }
}

export type NonceStoreHandle = {
  store: NonceStore;
  close: () => Promise<void>;
};

export async function createNonceStore(): Promise<NonceStoreHandle> {
  const url = process.env.REDIS_URL?.trim();
  const prod = (process.env.NODE_ENV ?? '').toLowerCase() === 'production';
  if (prod && !url) {
    throw new Error('REDIS_URL is required in production for replay protection');
  }
  if (url) {
    const { createClient } = await import('redis');
    const client = createClient({ url }) as RedisClientType;
    client.on('error', (err: Error) => {
      console.error('[backend-gateway] Redis error', err.message);
    });
    await client.connect();
    const prefix = process.env.REDIS_NONCE_PREFIX ?? 'banking:nonce:';
    return {
      store: new RedisNonceStore(client, prefix),
      close: async () => {
        await client.quit();
      },
    };
  }
  return {
    store: new InMemoryNonceStore(),
    close: async () => {},
  };
}
