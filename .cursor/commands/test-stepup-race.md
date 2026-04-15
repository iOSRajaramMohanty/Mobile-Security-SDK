Create concurrency test for step-up token.

Test:
- generate one step-up token
- send 2 concurrent /v1/secure requests with same token

Expected:
- exactly 1 succeeds
- other fails (token already consumed)

Output:
- automated test