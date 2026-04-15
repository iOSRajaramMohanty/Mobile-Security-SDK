-- Phase 4: PostgreSQL-backed device registry
-- Requires: CREATE EXTENSION privileges for pgcrypto (or pre-provisioned).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id text NOT NULL,
  key_id text NOT NULL UNIQUE,
  public_key_spki_der bytea NOT NULL,
  user_id text NULL,
  trusted boolean NOT NULL DEFAULT false,
  attestation_status text NOT NULL DEFAULT 'none',
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz NULL,
  revoked_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id);
CREATE INDEX IF NOT EXISTS idx_devices_key_id_active ON devices(key_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS device_audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id text NOT NULL,
  event_type text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_audit_logs_key_id ON device_audit_logs(key_id);
