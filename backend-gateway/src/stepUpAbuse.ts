import type { RedisClientType } from 'redis';

export interface StepUpAbuseGate {
  isBlocked(deviceId: string): Promise<boolean>;
  recordFailure(deviceId: string): Promise<void>;
  close(): Promise<void>;
}

export class InMemoryStepUpAbuseGate implements StepUpAbuseGate {
  private readonly failures = new Map<string, number[]>();
  constructor(
    private readonly windowMs: number,
    private readonly maxFailures: number,
  ) {}

  async isBlocked(deviceId: string): Promise<boolean> {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const arr = (this.failures.get(deviceId) ?? []).filter((t) => t >= cutoff);
    this.failures.set(deviceId, arr);
    return arr.length >= this.maxFailures;
  }

  async recordFailure(deviceId: string): Promise<void> {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const arr = (this.failures.get(deviceId) ?? []).filter((t) => t >= cutoff);
    arr.push(now);
    this.failures.set(deviceId, arr);
  }

  async close(): Promise<void> {}
}

export class RedisStepUpAbuseGate implements StepUpAbuseGate {
  constructor(
    private readonly client: RedisClientType,
    private readonly keyPrefix: string,
    private readonly windowMs: number,
    private readonly maxFailures: number,
  ) {}

  private key(deviceId: string): string {
    return `${this.keyPrefix}${deviceId}`;
  }

  async isBlocked(deviceId: string): Promise<boolean> {
    const v = await this.client.get(this.key(deviceId));
    const n = v ? Number(v) : 0;
    return Number.isFinite(n) && n >= this.maxFailures;
  }

  async recordFailure(deviceId: string): Promise<void> {
    const key = this.key(deviceId);
    const sec = Math.max(1, Math.ceil(this.windowMs / 1000));
    const n = await this.client.incr(key);
    // ensure TTL is set (idempotent)
    await this.client.expire(key, sec);
    void n;
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

export async function createStepUpAbuseGate(): Promise<StepUpAbuseGate> {
  const windowMs = Number(process.env.STEPUP_VERIFY_FAILURE_WINDOW_MS ?? 10 * 60_000);
  const maxFailures = Number(process.env.STEPUP_VERIFY_MAX_FAILURES ?? 10);
  const url = process.env.REDIS_URL?.trim();
  if (url) {
    const { createClient } = await import('redis');
    const client = createClient({ url }) as RedisClientType;
    client.on('error', (err: Error) => console.error('[backend-gateway] Redis error', err.message));
    await client.connect();
    const prefix = process.env.REDIS_STEPUP_FAIL_PREFIX ?? 'banking:stepup:fail:';
    return new RedisStepUpAbuseGate(client, prefix, windowMs, maxFailures);
  }
  return new InMemoryStepUpAbuseGate(windowMs, maxFailures);
}

