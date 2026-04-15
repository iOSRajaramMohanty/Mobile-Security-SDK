Validate production readiness:

SECURITY:
- upstream auth enforced
- no plaintext response
- _clientDek never exposed

TRUST:
- attestation required
- untrusted devices rejected

SCALING:
- Redis used for replay + rate limiting

CONFIG:
- fail-fast enabled

FAIL IF:
- any optional security path exists