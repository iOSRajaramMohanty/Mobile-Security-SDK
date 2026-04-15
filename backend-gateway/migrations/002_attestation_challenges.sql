-- One-time server-issued challenges for attestation nonce binding.

CREATE TABLE IF NOT EXISTS attestation_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id text NOT NULL,
  key_id text NOT NULL,
  platform text NOT NULL,
  nonce text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_attestation_challenges_lookup
  ON attestation_challenges(device_id, key_id, platform)
  WHERE used_at IS NULL;
