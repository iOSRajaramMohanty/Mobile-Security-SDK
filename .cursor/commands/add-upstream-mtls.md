Add mTLS support for upstream communication.

Requirements:

1. Load client certificate:
- UPSTREAM_MTLS_CERT_PEM_B64
- UPSTREAM_MTLS_KEY_PEM_B64

2. Load CA certificate:
- UPSTREAM_CA_CERT_PEM_B64

3. Configure HTTPS agent:
- Require client cert
- Validate server cert against CA

4. Enforce in production:
- If mTLS config missing → fail startup

5. Attach to all upstream calls

Reject:
- Any upstream call without mTLS in production

Output:
- HTTPS agent config
- Integration in forwarding layer