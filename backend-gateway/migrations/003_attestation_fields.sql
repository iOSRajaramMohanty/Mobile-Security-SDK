-- Add production attestation fields to devices.

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS integrity_level text NULL,
  ADD COLUMN IF NOT EXISTS verified_at timestamptz NULL,
  ADD COLUMN IF NOT EXISTS app_attest_public_key_pem text NULL,
  ADD COLUMN IF NOT EXISTS app_attest_sign_count bigint NULL;

