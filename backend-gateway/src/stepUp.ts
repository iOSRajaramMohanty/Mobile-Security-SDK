import crypto from 'node:crypto';
import type { RedisClientType } from 'redis';

export type StepUpChallenge = { challenge: string; expiresAtMs: number };

export type StepUpVerifyInput = {
  keyId: string;
  deviceId: string;
  path: string;
  method: string;
  payloadHash: string;
  challenge: string;
  signatureBase64: string;
};

export type StepUpTokenRecord = {
  keyId: string;
  deviceId: string;
  path: string;
  method: string;
  payloadHash: string;
  expiresAtMs: number;
};

export interface StepUpStore {
  issueChallenge(input: {
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
    ttlMs: number;
  }): Promise<StepUpChallenge>;
  consumeChallenge(input: {
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
    challenge: string;
  }): Promise<boolean>;
  issueToken(input: StepUpTokenRecord): Promise<string>;
  consumeToken(input: { token: string; keyId: string; deviceId: string; method: string; path: string; payloadHash: string }): Promise<boolean>;
  close(): Promise<void>;
}

function b64url(buf: Buffer): string {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function challengeKey(
  prefix: string,
  input: { keyId: string; deviceId: string; method: string; path: string; payloadHash: string; challenge: string },
): string {
  const pathHash = b64url(crypto.createHash('sha256').update(input.path, 'utf8').digest());
  const payloadHashHash = b64url(crypto.createHash('sha256').update(input.payloadHash, 'utf8').digest());
  return `${prefix}ch:${input.keyId}:${input.deviceId}:${input.method}:${pathHash}:${payloadHashHash}:${input.challenge}`;
}

function tokenKey(prefix: string, token: string): string {
  return `${prefix}tok:${token}`;
}

export function buildStepUpMessage(input: {
  keyId: string;
  method: string;
  path: string;
  payloadHash: string;
  challenge: string;
}): Buffer {
  // Stable, signed string to prevent confusion/replay across endpoints.
  const s = `stepup-v2|${input.keyId}|${input.method}|${input.path}|${input.payloadHash}|${input.challenge}`;
  return Buffer.from(s, 'utf8');
}

export class InMemoryStepUpStore implements StepUpStore {
  private readonly challenges = new Map<string, number>();
  private readonly tokens = new Map<string, StepUpTokenRecord>();

  async issueChallenge(input: {
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
    ttlMs: number;
  }): Promise<StepUpChallenge> {
    const challenge = b64url(crypto.randomBytes(32));
    const expiresAtMs = Date.now() + input.ttlMs;
    this.challenges.set(challengeKey('mem:', { ...input, challenge }), expiresAtMs);
    return { challenge, expiresAtMs };
  }

  async consumeChallenge(input: {
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
    challenge: string;
  }): Promise<boolean> {
    const k = challengeKey('mem:', input);
    const exp = this.challenges.get(k);
    if (!exp || exp < Date.now()) return false;
    this.challenges.delete(k);
    return true;
  }

  async issueToken(input: StepUpTokenRecord): Promise<string> {
    const token = b64url(crypto.randomBytes(32));
    this.tokens.set(token, input);
    return token;
  }

  async consumeToken(input: {
    token: string;
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
  }): Promise<boolean> {
    const rec = this.tokens.get(input.token);
    if (!rec) return false;
    if (rec.expiresAtMs < Date.now()) {
      this.tokens.delete(input.token);
      return false;
    }
    const ok =
      rec.keyId === input.keyId &&
      rec.deviceId === input.deviceId &&
      rec.method === input.method &&
      rec.path === input.path &&
      rec.payloadHash === input.payloadHash;
    if (ok) this.tokens.delete(input.token); // one-time use
    return ok;
  }

  async close(): Promise<void> {}
}

export class RedisStepUpStore implements StepUpStore {
  constructor(
    private readonly client: RedisClientType,
    private readonly keyPrefix: string,
  ) {}

  private async getDel(key: string): Promise<string | null> {
    // Prefer atomic GETDEL (Redis >= 6.2). Fallback to a Lua script if unavailable.
    const anyClient = this.client as any;
    if (typeof anyClient.getDel === 'function') {
      return (await anyClient.getDel(key)) as string | null;
    }
    // Atomic fallback.
    const lua = "local v=redis.call('GET',KEYS[1]); if v then redis.call('DEL',KEYS[1]); end; return v;";
    const out = await anyClient.eval(lua, { keys: [key], arguments: [] });
    return out == null ? null : String(out);
  }

  async issueChallenge(input: {
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
    ttlMs: number;
  }): Promise<StepUpChallenge> {
    const challenge = b64url(crypto.randomBytes(32));
    const expiresAtMs = Date.now() + input.ttlMs;
    const key = challengeKey(this.keyPrefix, { ...input, challenge });
    const sec = Math.max(1, Math.ceil(input.ttlMs / 1000));
    await this.client.set(key, '1', { EX: sec });
    return { challenge, expiresAtMs };
  }

  async consumeChallenge(input: {
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
    challenge: string;
  }): Promise<boolean> {
    const key = challengeKey(this.keyPrefix, input);
    // consume once (atomic)
    const v = await this.getDel(key);
    return v !== null;
  }

  async issueToken(input: StepUpTokenRecord): Promise<string> {
    const token = b64url(crypto.randomBytes(32));
    const key = tokenKey(this.keyPrefix, token);
    const ttlMs = Math.max(1, input.expiresAtMs - Date.now());
    const sec = Math.max(1, Math.ceil(ttlMs / 1000));
    await this.client.set(key, JSON.stringify(input), { EX: sec });
    return token;
  }

  async consumeToken(input: {
    token: string;
    keyId: string;
    deviceId: string;
    method: string;
    path: string;
    payloadHash: string;
  }): Promise<boolean> {
    const key = tokenKey(this.keyPrefix, input.token);
    // consume once globally (atomic)
    const raw = await this.getDel(key);
    if (!raw) return false;
    let rec: StepUpTokenRecord | null = null;
    try {
      rec = JSON.parse(raw) as StepUpTokenRecord;
    } catch {
      return false;
    }
    if (!rec) return false;
    if (rec.expiresAtMs < Date.now()) return false;
    return (
      rec.keyId === input.keyId &&
      rec.deviceId === input.deviceId &&
      rec.method === input.method &&
      rec.path === input.path &&
      rec.payloadHash === input.payloadHash
    );
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

export async function createStepUpStore(): Promise<StepUpStore> {
  const url = process.env.REDIS_URL?.trim();
  if (url) {
    const { createClient } = await import('redis');
    const client = createClient({ url }) as RedisClientType;
    client.on('error', (err: Error) => console.error('[backend-gateway] Redis error', err.message));
    await client.connect();
    const prefix = process.env.REDIS_STEPUP_PREFIX ?? 'banking:stepup:';
    return new RedisStepUpStore(client, prefix);
  }
  return new InMemoryStepUpStore();
}

