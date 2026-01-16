# CLI Reference

Complete command reference for QPKI.

## Command Tree

```
qpki [--audit-log PATH]
├── ca                        # Certificate Authority → CA.md
│   ├── init                  # Initialize CA (root or subordinate)
│   ├── info                  # Display CA information
│   ├── export                # Export CA certificates
│   ├── list                  # List CAs in directory
│   ├── rotate                # Rotate CA with new keys
│   ├── activate              # Activate pending CA version
│   └── versions              # List CA versions
│
├── cert                      # Certificate operations → CA.md
│   ├── issue                 # Issue certificate from CSR
│   ├── list                  # List issued certificates
│   ├── info                  # Display certificate info
│   ├── revoke                # Revoke a certificate
│   └── verify                # Verify certificate validity
│
├── credential                # Credentials → CREDENTIALS.md
│   ├── enroll                # Create new credential
│   ├── list                  # List credentials
│   ├── info                  # Credential details
│   ├── rotate                # Rotate credential
│   ├── activate              # Activate pending version
│   ├── versions              # List credential versions
│   ├── revoke                # Revoke credential
│   └── export                # Export credential
│
├── key                       # Key management → KEYS.md
│   ├── gen                   # Generate key pair
│   ├── pub                   # Extract public key
│   ├── list                  # List keys
│   ├── info                  # Key information
│   └── convert               # Convert key format
│
├── csr                       # CSR operations → KEYS.md
│   ├── gen                   # Generate CSR
│   ├── info                  # Display CSR info
│   └── verify                # Verify CSR signature
│
├── crl                       # CRL operations → CA.md
│   ├── gen                   # Generate CRL
│   ├── info                  # Display CRL info
│   ├── verify                # Verify CRL signature
│   └── list                  # List CRLs
│
├── profile                   # Certificate profiles → PROFILES.md
│   ├── list                  # List available profiles
│   ├── info                  # Profile details
│   ├── vars                  # Show profile variables
│   ├── show                  # Display YAML content
│   ├── export                # Export profile to file
│   ├── lint                  # Validate profile YAML
│   └── install               # Install default profiles
│
├── tsa                       # Timestamping → TSA.md
│   ├── sign                  # Create timestamp token
│   ├── verify                # Verify timestamp token
│   └── serve                 # Start TSA HTTP server
│
├── cms                       # CMS signatures → CMS.md
│   ├── sign                  # Create CMS signature
│   ├── verify                # Verify CMS signature
│   ├── encrypt               # Encrypt with CMS
│   ├── decrypt               # Decrypt CMS
│   └── info                  # Display CMS info
│
├── ocsp                      # OCSP responder → OCSP.md
│   ├── sign                  # Create OCSP response
│   ├── verify                # Verify OCSP response
│   ├── request               # Create OCSP request
│   ├── info                  # Display OCSP response info
│   └── serve                 # Start OCSP HTTP server
│
├── hsm                       # HSM integration → HSM.md
│   ├── list                  # List HSM slots/tokens
│   ├── test                  # Test HSM connectivity
│   └── info                  # Display HSM token info
│
├── audit                     # Audit logging → AUDIT.md
│   ├── verify                # Verify audit log integrity
│   └── tail                  # Show recent audit events
│
└── inspect                   # Auto-detect and display file info
```

---

## Quick Reference

| Category | Command | Description | Documentation |
|----------|---------|-------------|---------------|
| **Keys** | `key gen` | Generate a private key | [KEYS.md](KEYS.md) |
| | `key pub` | Extract public key | [KEYS.md](KEYS.md) |
| | `key list` | List keys in directory | [KEYS.md](KEYS.md) |
| | `key info` | Display key details | [KEYS.md](KEYS.md) |
| | `key convert` | Convert key format | [KEYS.md](KEYS.md) |
| **CA** | `ca init` | Initialize a certificate authority | [CA.md](CA.md) |
| | `ca info` | Display CA information | [CA.md](CA.md) |
| | `ca export` | Export CA certificates | [CA.md](CA.md) |
| | `ca list` | List CAs in directory | [CA.md](CA.md) |
| | `ca rotate` | Rotate CA with new keys | [CA.md](CA.md) |
| | `ca activate` | Activate a pending version | [CA.md](CA.md) |
| | `ca versions` | List CA versions | [CA.md](CA.md) |
| **CSR** | `csr gen` | Generate a certificate signing request | [KEYS.md](KEYS.md) |
| | `csr info` | Display CSR details | [KEYS.md](KEYS.md) |
| | `csr verify` | Verify CSR signature | [KEYS.md](KEYS.md) |
| **Certificates** | `cert issue` | Issue certificate from CSR | [CA.md](CA.md) |
| | `cert list` | List certificates in CA | [CA.md](CA.md) |
| | `cert info` | Display certificate details | [CA.md](CA.md) |
| | `cert revoke` | Revoke a certificate | [CA.md](CA.md) |
| | `cert verify` | Verify a certificate | [CA.md](CA.md) |
| **Credentials** | `credential enroll` | Issue key(s) + certificate(s) | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential list` | List credentials | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential info` | Credential details | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential rotate` | Rotate a credential | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential activate` | Activate pending version | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential versions` | List credential versions | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential revoke` | Revoke a credential | [CREDENTIALS.md](CREDENTIALS.md) |
| | `credential export` | Export credential | [CREDENTIALS.md](CREDENTIALS.md) |
| **CRL** | `crl gen` | Generate a CRL | [CA.md](CA.md) |
| | `crl info` | Display CRL details | [CA.md](CA.md) |
| | `crl verify` | Verify a CRL | [CA.md](CA.md) |
| | `crl list` | List CRLs in CA | [CA.md](CA.md) |
| **Profiles** | `profile list` | List available profiles | [PROFILES.md](PROFILES.md) |
| | `profile info` | Display profile details | [PROFILES.md](PROFILES.md) |
| | `profile vars` | List profile variables | [PROFILES.md](PROFILES.md) |
| | `profile show` | Display profile YAML | [PROFILES.md](PROFILES.md) |
| | `profile export` | Export a profile | [PROFILES.md](PROFILES.md) |
| | `profile lint` | Validate profile YAML | [PROFILES.md](PROFILES.md) |
| | `profile install` | Install default profiles | [PROFILES.md](PROFILES.md) |
| **Inspection** | `inspect` | Inspect certificate, key, or CRL | - |
| **CMS** | `cms sign` | Create CMS signature | [CMS.md](CMS.md) |
| | `cms verify` | Verify CMS signature | [CMS.md](CMS.md) |
| | `cms encrypt` | Encrypt with CMS | [CMS.md](CMS.md) |
| | `cms decrypt` | Decrypt CMS | [CMS.md](CMS.md) |
| | `cms info` | Display CMS message details | [CMS.md](CMS.md) |
| **TSA** | `tsa sign` | Timestamp a file | [TSA.md](TSA.md) |
| | `tsa verify` | Verify timestamp token | [TSA.md](TSA.md) |
| | `tsa serve` | Start TSA HTTP server | [TSA.md](TSA.md) |
| **OCSP** | `ocsp sign` | Create OCSP response | [OCSP.md](OCSP.md) |
| | `ocsp verify` | Verify OCSP response | [OCSP.md](OCSP.md) |
| | `ocsp request` | Create OCSP request | [OCSP.md](OCSP.md) |
| | `ocsp info` | Display OCSP response info | [OCSP.md](OCSP.md) |
| | `ocsp serve` | Start OCSP HTTP server | [OCSP.md](OCSP.md) |
| **HSM** | `hsm list` | List HSM slots/tokens | [HSM.md](HSM.md) |
| | `hsm test` | Test HSM connectivity | [HSM.md](HSM.md) |
| | `hsm info` | Display HSM token info | [HSM.md](HSM.md) |
| **Audit** | `audit verify` | Verify audit log integrity | [AUDIT.md](AUDIT.md) |
| | `audit tail` | Show recent audit events | [AUDIT.md](AUDIT.md) |

---

## Global Flags

| Flag | Environment Variable | Description |
|------|---------------------|-------------|
| `--audit-log PATH` | `PKI_AUDIT_LOG` | Enable audit logging to file |

---

## Supported Algorithms

**Classical:**
- `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`
- `ed25519`
- `rsa-2048`, `rsa-4096`

**Post-Quantum (FIPS 204/205/203):**
- `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` (signature)
- `slh-dsa-128s`, `slh-dsa-192s`, `slh-dsa-256s` (signature, hash-based)
- `ml-kem-512`, `ml-kem-768`, `ml-kem-1024` (key encapsulation)

**Hybrid modes:**
- Catalyst (ITU-T X.509 Section 9.8)
- Composite (IETF draft-13)

See [CONCEPTS.md](CONCEPTS.md) for algorithm details.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid input, operation failed, etc.) |

---

## See Also

- [CA](CA.md) - CA and certificate operations
- [KEYS](KEYS.md) - Key and CSR operations
- [CREDENTIALS](CREDENTIALS.md) - Credential lifecycle
- [PROFILES](PROFILES.md) - Certificate profiles
- [OCSP](OCSP.md) - OCSP responder
- [TSA](TSA.md) - Timestamping
- [CMS](CMS.md) - CMS signatures and encryption
- [AUDIT](AUDIT.md) - Audit logging
- [HSM](HSM.md) - HSM integration
