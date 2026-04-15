import type pg from 'pg';

export type DeviceRow = {
  deviceId: string;
  keyId: string;
  publicKeySpkiDer: Buffer;
  userId: string | null;
  trusted: boolean;
  attestationStatus: string;
  integrityLevel: string | null;
  verifiedAt: Date | null;
  appAttestPublicKeyPem: string | null;
  appAttestSignCount: bigint | null;
  createdAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
};

export type AuditEventType = 'REGISTERED' | 'ROTATED' | 'REVOKED' | 'ATTESTED';

export interface DeviceRepository {
  getByKeyId(keyId: string): Promise<DeviceRow | null>;
  getActiveByDeviceId(deviceId: string): Promise<DeviceRow | null>;
  insertDevice(input: {
    deviceId: string;
    keyId: string;
    publicKeySpkiDer: Buffer;
    platform: string;
    userId?: string | null;
  }): Promise<DeviceRow>;
  revokeByKeyId(keyId: string, metadata?: Record<string, unknown>): Promise<void>;
  setTrusted(
    keyId: string,
    input: {
      trusted: boolean;
      attestationStatus: string;
      integrityLevel?: string | null;
      verifiedAt?: Date | null;
      appAttestPublicKeyPem?: string | null;
      appAttestSignCount?: bigint | null;
    },
    metadata?: Record<string, unknown>,
  ): Promise<void>;
  insertAuditLog(keyId: string, eventType: AuditEventType, metadata?: Record<string, unknown>): Promise<void>;
  insertAttestationChallenge(input: {
    deviceId: string;
    keyId: string;
    platform: string;
    nonce: string;
    expiresAt: Date;
  }): Promise<void>;
  consumeAttestationChallenge(input: {
    deviceId: string;
    keyId: string;
    platform: string;
  }): Promise<{ nonce: string } | null>;
}

export class PgDeviceRepository implements DeviceRepository {
  constructor(private readonly pool: pg.Pool) {}

  async getByKeyId(keyId: string): Promise<DeviceRow | null> {
    const r = await this.pool.query(
      `SELECT device_id, key_id, public_key_spki_der, user_id, trusted, attestation_status,
              integrity_level, verified_at, app_attest_public_key_pem, app_attest_sign_count,
              created_at, rotated_at, revoked_at
       FROM devices
       WHERE key_id = $1
       LIMIT 1`,
      [keyId],
    );
    if (r.rowCount === 0) return null;
    return mapDeviceRow(r.rows[0]);
  }

  async getActiveByDeviceId(deviceId: string): Promise<DeviceRow | null> {
    const r = await this.pool.query(
      `SELECT device_id, key_id, public_key_spki_der, user_id, trusted, attestation_status,
              integrity_level, verified_at, app_attest_public_key_pem, app_attest_sign_count,
              created_at, rotated_at, revoked_at
       FROM devices
       WHERE device_id = $1 AND revoked_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [deviceId],
    );
    if (r.rowCount === 0) return null;
    return mapDeviceRow(r.rows[0]);
  }

  async insertDevice(input: {
    deviceId: string;
    keyId: string;
    publicKeySpkiDer: Buffer;
    platform: string;
    userId?: string | null;
  }): Promise<DeviceRow> {
    // Never trust client-provided trust flags; trusted is always false at insert.
    const r = await this.pool.query(
      `INSERT INTO devices (device_id, key_id, public_key_spki_der, user_id, trusted, attestation_status, integrity_level, verified_at, app_attest_public_key_pem, app_attest_sign_count, rotated_at, revoked_at)
       VALUES ($1, $2, $3, $4, false, 'none', NULL, NULL, NULL, NULL, NULL, NULL)
       RETURNING device_id, key_id, public_key_spki_der, user_id, trusted, attestation_status,
                 integrity_level, verified_at, app_attest_public_key_pem, app_attest_sign_count,
                 created_at, rotated_at, revoked_at`,
      [input.deviceId, input.keyId, input.publicKeySpkiDer, input.userId ?? null],
    );
    return mapDeviceRow(r.rows[0]);
  }

  async revokeByKeyId(keyId: string, metadata: Record<string, unknown> = {}): Promise<void> {
    await this.pool.query(`UPDATE devices SET revoked_at = now() WHERE key_id = $1 AND revoked_at IS NULL`, [keyId]);
    await this.insertAuditLog(keyId, 'REVOKED', metadata);
  }

  async setTrusted(
    keyId: string,
    input: {
      trusted: boolean;
      attestationStatus: string;
      integrityLevel?: string | null;
      verifiedAt?: Date | null;
      appAttestPublicKeyPem?: string | null;
      appAttestSignCount?: bigint | null;
    },
    metadata: Record<string, unknown> = {},
  ): Promise<void> {
    await this.pool.query(
      `UPDATE devices
       SET trusted = $2,
           attestation_status = $3,
           integrity_level = $4,
           verified_at = $5,
           app_attest_public_key_pem = $6,
           app_attest_sign_count = $7
       WHERE key_id = $1`,
      [
        keyId,
        input.trusted,
        input.attestationStatus,
        input.integrityLevel ?? null,
        input.verifiedAt ?? new Date(),
        input.appAttestPublicKeyPem ?? null,
        input.appAttestSignCount ?? null,
      ],
    );
    await this.insertAuditLog(keyId, 'ATTESTED', { trusted: input.trusted, attestationStatus: input.attestationStatus, ...metadata });
  }

  async insertAuditLog(keyId: string, eventType: AuditEventType, metadata: Record<string, unknown> = {}): Promise<void> {
    await this.pool.query(
      `INSERT INTO device_audit_logs (key_id, event_type, metadata)
       VALUES ($1, $2, $3::jsonb)`,
      [keyId, eventType, JSON.stringify(metadata)],
    );
  }

  async insertAttestationChallenge(input: {
    deviceId: string;
    keyId: string;
    platform: string;
    nonce: string;
    expiresAt: Date;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO attestation_challenges (device_id, key_id, platform, nonce, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [input.deviceId, input.keyId, input.platform, input.nonce, input.expiresAt],
    );
  }

  async consumeAttestationChallenge(input: {
    deviceId: string;
    keyId: string;
    platform: string;
  }): Promise<{ nonce: string } | null> {
    const r = await this.pool.query(
      `UPDATE attestation_challenges
       SET used_at = now()
       WHERE id = (
         SELECT id FROM attestation_challenges
         WHERE device_id = $1 AND key_id = $2 AND platform = $3
           AND used_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC
         LIMIT 1
       )
       RETURNING nonce`,
      [input.deviceId, input.keyId, input.platform],
    );
    if (r.rowCount === 0) return null;
    return { nonce: String(r.rows[0].nonce) };
  }
}

function mapDeviceRow(r: any): DeviceRow {
  return {
    deviceId: String(r.device_id),
    keyId: String(r.key_id),
    publicKeySpkiDer: Buffer.from(r.public_key_spki_der),
    userId: r.user_id == null ? null : String(r.user_id),
    trusted: Boolean(r.trusted),
    attestationStatus: String(r.attestation_status),
    integrityLevel: r.integrity_level == null ? null : String(r.integrity_level),
    verifiedAt: r.verified_at ? new Date(r.verified_at) : null,
    appAttestPublicKeyPem: r.app_attest_public_key_pem == null ? null : String(r.app_attest_public_key_pem),
    appAttestSignCount: r.app_attest_sign_count == null ? null : BigInt(r.app_attest_sign_count),
    createdAt: new Date(r.created_at),
    rotatedAt: r.rotated_at ? new Date(r.rotated_at) : null,
    revokedAt: r.revoked_at ? new Date(r.revoked_at) : null,
  };
}

