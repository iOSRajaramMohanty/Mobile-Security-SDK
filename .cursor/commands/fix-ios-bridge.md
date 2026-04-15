Fix React Native iOS bridge.

Requirements:
- Bridge MUST call Swift SecuritySdk
- Remove duplicate logic in Objective-C layer
- Ensure single source of truth

Output:
- Updated bridge
- Verified integration