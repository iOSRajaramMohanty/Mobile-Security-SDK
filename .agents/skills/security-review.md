Act as a senior security auditor for a banking-grade SDK.

Check for:

CRYPTO ISSUES:
- Weak algorithms
- Missing encryption
- Incorrect key usage
- Lack of authentication (GCM tag, signature)

KEY MANAGEMENT:
- Private key exposure
- Keys stored outside secure hardware
- Missing rotation

REACT NATIVE RISKS:
- Any crypto logic in JS (STRICTLY FORBIDDEN)
- Sensitive data passed to JS layer
- Improper bridge usage

NETWORK SECURITY:
- Missing certificate pinning
- No payload encryption
- Missing signature validation

API SECURITY:
- Missing nonce/timestamp
- Replay attack vulnerability
- Missing validation

RUNTIME SECURITY:
- No root/jailbreak detection
- No anti-debugging
- No anti-hooking

CODE QUALITY:
- Hardcoded secrets
- Improper error handling
- Logging sensitive data

OUTPUT:
- List vulnerabilities
- Severity (High/Medium/Low)
- Fix recommendations