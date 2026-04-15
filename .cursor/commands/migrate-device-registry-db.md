Implement production-grade device registry using PostgreSQL.

ARCHITECTURE:
- Use repository pattern
- No direct DB calls in route handlers

TABLES:

devices:
- id (uuid, pk)
- deviceId (text, indexed)
- keyId (text, unique)
- publicKeySpkiDer (bytea)
- userId (nullable)
- trusted (boolean, default false)
- attestationStatus (text)
- createdAt (timestamp)
- rotatedAt (timestamp)
- revokedAt (timestamp)

device_audit_logs:
- id
- keyId
- eventType (REGISTERED, ROTATED, REVOKED, ATTESTED)
- metadata (jsonb)
- createdAt

REQUIREMENTS:
- Unique constraint on keyId
- Index on deviceId
- Soft delete via revokedAt
- Audit log on every change

OPERATIONS:

registerDevice:
- Insert new device
- trusted = false initially

verifyDevice:
- Fetch by keyId
- Reject if revokedAt != null

rotateKey:
- Mark old key revoked
- Insert new key
- Require attestation

revokeDevice:
- Set revokedAt

SECURITY RULES:
- Never overwrite keys
- Never trust client-provided trust flags
- All trust must come from attestation

OUTPUT:
- SQL schema
- Repository layer
- Service layer
- Migration scripts