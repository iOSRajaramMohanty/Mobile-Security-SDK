flowchart TD

A[Mobile App<br/>(React Native / Native)]
B[Native Security SDK<br/>Crypto + Keys + Attestation]
C[Secure Gateway]
D[Trust Layer<br/>Attestation + Device Binding]
E[Security Controls<br/>Replay + Rate Limit + Step-Up]
F[Forwarding Layer<br/>Allowlist + Validation]
G[Internal Services]
H[Encrypted Response]

A --> B
B --> C

C --> D
C --> E
C --> F

F --> G
G --> H
H --> B

---

subgraph Security Guarantees
I[End-to-End Encryption]
J[Certificate Pinning]
K[mTLS Internal]
L[No Plaintext Exposure]
end

B --> I
B --> J
F --> K
C --> L