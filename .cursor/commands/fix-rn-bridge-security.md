Harden React Native bridge.

Add:
- Payload size limits
- Input validation
- Safe JSON parsing
- Error redaction (no stack traces)

Remove:
- Passing raw exceptions to JS