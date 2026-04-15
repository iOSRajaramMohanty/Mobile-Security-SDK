Add production fail-fast checks.

On startup (NODE_ENV=production):

REQUIRE:
- REDIS_URL
- INTERNAL_UPSTREAM_BASE_URL
- INTERNAL_UPSTREAM_AUTH_TOKEN
- FORWARD_ALLOWLIST_PATHS

Crash if missing.

Also:
- validate URL format
- reject localhost/public URLs for upstream