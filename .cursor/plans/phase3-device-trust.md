Goal: Implement Device Trust & Binding System

Core Objectives:
- Bind cryptographic identity to a real device
- Prevent self-generated attacker keys
- Enforce zero-trust backend validation

Scope:

1. Device Enrollment Flow
2. Server-side Key Registry
3. Request Validation Against Registry
4. Optional Attestation (Play Integrity / App Attest)
5. Replay protection (multi-instance safe)
6. Protocol hardening (version + algorithm enforcement)

Constraints:
- Backend must NEVER trust client-provided public keys
- All device keys must be pre-registered
- Unknown keys must be rejected

Deliverables:
- Device registration API
- Device key database
- Validation middleware
- Updated SDK enrollment flow

Exit Criteria:
- Requests signed by unknown keys are rejected
- Device identity is enforced server-side