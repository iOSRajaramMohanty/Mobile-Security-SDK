import type { RedisClientType } from 'redis';

export type RateLimitDecision = { ok: true } | { ok: false; reason: 'rate_limited' };

export interface DeviceRateLimiter {
  check(input: { endpoint: string; deviceId: string; windowMs: number; max: number }): Promise<RateLimitDecision>;
  close(): Promise<void>;
}

export class InMemoryDeviceRateLimiter implements DeviceRateLimiter {
  private readonly hits = new Map<string, number[]>();

  async check(input: { endpoint: string; deviceId: string; windowMs: number; max: number }): Promise<RateLimitDecision> {
    const now = Date.now();
    const cutoff = now - input.windowMs;
    const key = `${input.endpoint}:${input.deviceId}`;
    const arr = (this.hits.get(key) ?? []).filter((t) => t >= cutoff);
    arr.push(now);
    this.hits.set(key, arr);
    return arr.length > input.max ? { ok: false, reason: 'rate_limited' } : { ok: true };
  }

  async close(): Promise<void> {}
}

export class RedisDeviceRateLimiter implements DeviceRateLimiter {
  constructor(
    private readonly client: RedisClientType,
    private readonly keyPrefix: string,
  ) {}

  async check(input: { endpoint: string; deviceId: string; windowMs: number; max: number }): Promise<RateLimitDecision> {
    const now = Date.now();
    const key = `${this.keyPrefix}${input.endpoint}:${input.deviceId}`;
    const cutoff = now - input.windowMs;
    const ttlSec = Math.max(1, Math.ceil(input.windowMs / 1000));

    // Sliding window using ZSET.
    // - add current timestamp
    // - prune old
    // - count
    // - expire
    const multi = this.client.multi();
    multi.zAdd(key, [{ score: now, value: String(now) }]);
    multi.zRemRangeByScore(key, 0, cutoff);
    multi.zCard(key);
    multi.expire(key, ttlSec);
    const out = (await multi.exec()) as unknown[];

    // zCard is 3rd command output (index 2)
    const count = Number((out?.[2] as any) ?? 0);
    if (!Number.isFinite(count)) return { ok: true };
    return count > input.max ? { ok: false, reason: 'rate_limited' } : { ok: true };
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

export async function createDeviceRateLimiter(): Promise<DeviceRateLimiter> {
  const url = process.env.REDIS_URL?.trim();
  if (url) {
    const { createClient } = await import('redis');
    const client = createClient({ url }) as RedisClientType;
    client.on('error', (err: Error) => {
      console.error('[backend-gateway] Redis error', err.message);
    });
    await client.connect();
    const prefix = process.env.REDIS_RATE_LIMIT_PREFIX ?? 'banking:rl:';
    return new RedisDeviceRateLimiter(client, prefix);
  }
  return new InMemoryDeviceRateLimiter();
}

