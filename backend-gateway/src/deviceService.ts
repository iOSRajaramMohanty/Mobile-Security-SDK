import type { DeviceRepository, DeviceRow } from './deviceRepo.js';

export class DeviceService {
  constructor(private readonly repo: DeviceRepository) {}

  async registerDevice(input: {
    deviceId: string;
    keyId: string;
    publicKeySpkiDer: Buffer;
    platform: string;
    userId?: string | null;
  }): Promise<{ status: 'created' | 'unchanged'; device: DeviceRow }> {
    const existingByKey = await this.repo.getByKeyId(input.keyId);
    if (existingByKey && !existingByKey.revokedAt) {
      // Idempotent if key already registered.
      return { status: 'unchanged', device: existingByKey };
    }

    const active = await this.repo.getActiveByDeviceId(input.deviceId);
    if (active && active.keyId !== input.keyId) {
      // Phase 4 rule: never overwrite keys. Rotation is a separate operation requiring attestation.
      throw new Error('device_already_registered');
    }

    const device = await this.repo.insertDevice(input);
    await this.repo.insertAuditLog(device.keyId, 'REGISTERED', { platform: input.platform });
    return { status: 'created', device };
  }

  async verifyDevice(keyId: string): Promise<DeviceRow | null> {
    const d = await this.repo.getByKeyId(keyId);
    if (!d || d.revokedAt) return null;
    return d;
  }

  async setTrusted(keyId: string, trusted: boolean, attestationStatus: string, metadata: Record<string, unknown> = {}) {
    await this.repo.setTrusted(keyId, { trusted, attestationStatus }, metadata);
  }

  async setAttestationDetails(input: {
    keyId: string;
    trusted: boolean;
    attestationStatus: string;
    integrityLevel?: string | null;
    verifiedAt?: Date | null;
    appAttestPublicKeyPem?: string | null;
    appAttestSignCount?: bigint | null;
    metadata?: Record<string, unknown>;
  }) {
    await this.repo.setTrusted(
      input.keyId,
      {
        trusted: input.trusted,
        attestationStatus: input.attestationStatus,
        integrityLevel: input.integrityLevel ?? null,
        verifiedAt: input.verifiedAt ?? new Date(),
        appAttestPublicKeyPem: input.appAttestPublicKeyPem ?? null,
        appAttestSignCount: input.appAttestSignCount ?? null,
      },
      input.metadata ?? {},
    );
  }

  async revokeDevice(keyId: string, metadata: Record<string, unknown> = {}) {
    await this.repo.revokeByKeyId(keyId, metadata);
  }
}

