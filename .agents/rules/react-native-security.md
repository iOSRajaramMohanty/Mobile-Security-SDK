React Native Security Enforcement Rules:

STRICTLY FORBIDDEN:
- Implementing encryption in JavaScript
- Storing secrets in AsyncStorage
- Passing private keys to JS
- Performing signing in JS

ALLOWED:
- Calling native SDK methods
- Passing non-sensitive payloads to native
- Receiving processed results

BRIDGE RULES:
- Validate all inputs before passing to native
- Handle errors safely
- Do not leak sensitive data in responses

PRODUCTION RULES:
- Disable debug mode
- Enable JS bundle minification
- Enable native code obfuscation

FAIL ANY CODE THAT:
- Violates native-only crypto rule
- Exposes sensitive data