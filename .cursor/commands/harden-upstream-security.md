Harden upstream forwarding security.

Requirements:

1. REQUIRE upstream authentication
- Add INTERNAL_UPSTREAM_AUTH_TOKEN
- Attach as header in all forwarded requests

2. FAIL-FAST in production:
- If INTERNAL_UPSTREAM_BASE_URL missing → crash
- If AUTH token missing → crash

3. Enforce private network:
- Only allow internal/private IP ranges
- Reject public URLs in production

4. Optional (recommended):
- Support mTLS between gateway and upstream

Reject:
- any forwarding without auth