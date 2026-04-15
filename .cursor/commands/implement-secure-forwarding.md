Replace echo response with secure forwarding layer.

FLOW:

1. Decrypt + verify request
2. Validate:
   - device trust
   - attestation
   - risk score
3. Map request to internal API

Forward:
- Only allowlisted endpoints
- Strip sensitive metadata (keys, signatures)

Call:
- Internal service (HTTP/gRPC)

On response:
- Validate response schema
- Encrypt response using client public key

SECURITY RULES:
- Never forward raw encrypted payload
- Never log decrypted sensitive data
- Enforce allowlist of routes

OUTPUT:
- forwarding service
- route mapping config
- response encryption logic