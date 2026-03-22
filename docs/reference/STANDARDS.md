---
title: "Standards Reference"
description: "Implemented standards, OID registry, X.509 extensions, and file formats reference."
---

# Standards Reference

## 1. Implemented Standards

### 1.1 X.509 & PKI Services

| Standard | Title | Link |
|----------|-------|------|
| RFC 2986 | PKCS #10: Certification Request Syntax Specification | [datatracker](https://datatracker.ietf.org/doc/html/rfc2986) |
| RFC 3161 | Internet X.509 PKI Time-Stamp Protocol (TSP) | [datatracker](https://datatracker.ietf.org/doc/html/rfc3161) |
| RFC 3739 | Internet X.509 PKI Qualified Certificates Profile | [datatracker](https://datatracker.ietf.org/doc/html/rfc3739) |
| RFC 4055 | Additional Algorithms for RSA Cryptography in X.509 | [datatracker](https://datatracker.ietf.org/doc/html/rfc4055) |
| RFC 5280 | Internet X.509 PKI Certificate and CRL Profile | [datatracker](https://datatracker.ietf.org/doc/html/rfc5280) |
| RFC 6960 | Online Certificate Status Protocol (OCSP) | [datatracker](https://datatracker.ietf.org/doc/html/rfc6960) |
| RFC 8017 | PKCS #1: RSA Cryptography Specifications Version 2.2 | [datatracker](https://datatracker.ietf.org/doc/html/rfc8017) |

### 1.2 Post-Quantum Cryptography

| Standard | Title | Link |
|----------|-------|------|
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) | [csrc.nist.gov](https://csrc.nist.gov/pubs/fips/203/final) |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard (ML-DSA) | [csrc.nist.gov](https://csrc.nist.gov/pubs/fips/204/final) |
| FIPS 205 | Stateless Hash-Based Digital Signature Standard (SLH-DSA) | [csrc.nist.gov](https://csrc.nist.gov/pubs/fips/205/final) |
| RFC 9879 | Use of SLH-DSA in X.509 Certificates | [datatracker](https://datatracker.ietf.org/doc/html/rfc9879) |
| RFC 9881 | Use of ML-DSA in X.509 Certificates | [datatracker](https://datatracker.ietf.org/doc/html/rfc9881) |
| RFC 9883 | Use of ML-KEM in Certification Request Attestation | [datatracker](https://datatracker.ietf.org/doc/html/rfc9883) |

### 1.3 Hybrid & Composite

| Standard | Title | Link |
|----------|-------|------|
| ITU-T X.509 §9.8 | Catalyst certificates (alternative signature extensions) | [itu.int](https://www.itu.int/rec/T-REC-X.509) |
| draft-ounsworth-pq-composite-sigs-13 | Composite ML-DSA Signatures for X.509 | [datatracker](https://datatracker.ietf.org/doc/draft-ounsworth-pq-composite-sigs/) |
| draft-ietf-lamps-cert-binding-for-multi-auth-06 | Certificate Binding for Multi-Authentication | [datatracker](https://datatracker.ietf.org/doc/draft-ietf-lamps-cert-binding-for-multi-auth/) |

### 1.4 CMS & S/MIME

| Standard | Title | Link |
|----------|-------|------|
| RFC 5083 | CMS Authenticated-Enveloped-Data Content Type | [datatracker](https://datatracker.ietf.org/doc/html/rfc5083) |
| RFC 5652 | Cryptographic Message Syntax (CMS) | [datatracker](https://datatracker.ietf.org/doc/html/rfc5652) |
| RFC 8419 | Use of EdDSA Signatures in CMS | [datatracker](https://datatracker.ietf.org/doc/html/rfc8419) |
| RFC 8550 | S/MIME Version 4.0 Certificate Handling | [datatracker](https://datatracker.ietf.org/doc/html/rfc8550) |
| RFC 8551 | S/MIME Version 4.0 Message Specification | [datatracker](https://datatracker.ietf.org/doc/html/rfc8551) |
| RFC 9629 | Using Key Encapsulation Mechanisms in CMS | [datatracker](https://datatracker.ietf.org/doc/html/rfc9629) |
| RFC 9814 | Use of SLH-DSA in CMS | [datatracker](https://datatracker.ietf.org/doc/html/rfc9814) |
| RFC 9880 | Use of ML-KEM in CMS | [datatracker](https://datatracker.ietf.org/doc/html/rfc9880) |
| RFC 9882 | Use of ML-DSA in CMS | [datatracker](https://datatracker.ietf.org/doc/html/rfc9882) |

### 1.5 COSE / CBOR

| Standard | Title | Link |
|----------|-------|------|
| RFC 8392 | CBOR Web Token (CWT) | [datatracker](https://datatracker.ietf.org/doc/html/rfc8392) |
| RFC 8949 | Concise Binary Object Representation (CBOR) | [datatracker](https://datatracker.ietf.org/doc/html/rfc8949) |
| RFC 9052 | COSE: Structures and Process | [datatracker](https://datatracker.ietf.org/doc/html/rfc9052) |
| RFC 9053 | COSE: Initial Algorithms | [datatracker](https://datatracker.ietf.org/doc/html/rfc9053) |
| RFC 9360 | COSE Header Parameters for X.509 Certificates | [datatracker](https://datatracker.ietf.org/doc/html/rfc9360) |
| draft-ietf-cose-dilithium-04 | COSE Algorithm Identifiers for ML-DSA | [datatracker](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/) |

### 1.6 TLS & SSH

| Standard | Title | Link |
|----------|-------|------|
| RFC 5246 | TLS Protocol Version 1.2 | [datatracker](https://datatracker.ietf.org/doc/html/rfc5246) |
| RFC 8446 | TLS Protocol Version 1.3 | [datatracker](https://datatracker.ietf.org/doc/html/rfc8446) |
| OpenSSH PROTOCOL.certkeys | OpenSSH Certificate Key Format | [github](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys) |

### 1.7 Compliance & Security

| Standard | Title | Link |
|----------|-------|------|
| FIPS 140-3 | Security Requirements for Cryptographic Modules | [csrc.nist.gov](https://csrc.nist.gov/pubs/fips/140-3/final) |
| NIST SP 800-57 | Recommendation for Key Management | [csrc.nist.gov](https://csrc.nist.gov/pubs/sp/800-57-pt1/r5/final) |
| EU 910/2014 | eIDAS Regulation | [eur-lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32014R0910) |
| ETSI EN 319 401 | General Policy Requirements for Trust Service Providers | [etsi.org](https://www.etsi.org/deliver/etsi_en/319400_319499/319401/) |
| ETSI EN 319 412-5 | QCStatements Extension for Qualified Certificates | [etsi.org](https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/) |
| ETSI EN 319 422 | Time-Stamping Protocol and Token Profiles | [etsi.org](https://www.etsi.org/deliver/etsi_en/319400_319499/319422/) |

## 2. OID Registry

### 2.1 Classical Algorithm OIDs

| Algorithm | OID |
|-----------|-----|
| RSA | 1.2.840.113549.1.1.1 |
| ECDSA P-256 | 1.2.840.10045.3.1.7 |
| ECDSA P-384 | 1.3.132.0.34 |
| ECDSA P-521 | 1.3.132.0.35 |
| Ed25519 | 1.3.101.112 |

### 2.2 Post-Quantum Algorithm OIDs

| Algorithm | OID |
|-----------|-----|
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 |
| SLH-DSA-SHA2-128s | 2.16.840.1.101.3.4.3.20 |
| SLH-DSA-SHA2-128f | 2.16.840.1.101.3.4.3.21 |
| SLH-DSA-SHA2-192s | 2.16.840.1.101.3.4.3.22 |
| SLH-DSA-SHA2-192f | 2.16.840.1.101.3.4.3.23 |
| SLH-DSA-SHA2-256s | 2.16.840.1.101.3.4.3.24 |
| SLH-DSA-SHA2-256f | 2.16.840.1.101.3.4.3.25 |
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 |

### 2.3 Hybrid Extension OIDs

**Catalyst (ITU-T X.509 §9.8):**

| OID | Name |
|-----|------|
| 2.5.29.72 | AltSubjectPublicKeyInfo |
| 2.5.29.73 | AltSignatureAlgorithm |
| 2.5.29.74 | AltSignatureValue |

**Composite (IANA-allocated):**

| Algorithm | OID |
|-----------|-----|
| MLDSA65-ECDSA-P256-SHA512 | 1.3.6.1.5.5.7.6.45 |
| MLDSA65-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.46 |
| MLDSA87-ECDSA-P521-SHA512 | 1.3.6.1.5.5.7.6.54 |

### 2.4 X.509 Extension OIDs

| OID | Name | Usage |
|-----|------|-------|
| 2.5.29.14 | Subject Key Identifier | Certificate extension |
| 2.5.29.15 | Key Usage | Certificate extension |
| 2.5.29.17 | Subject Alternative Name | Certificate extension |
| 2.5.29.19 | Basic Constraints | Certificate extension |
| 2.5.29.31 | CRL Distribution Points | Certificate extension |
| 2.5.29.35 | Authority Key Identifier | Certificate extension |
| 2.5.29.37 | Extended Key Usage | Certificate extension |

## 3. File Formats

### 3.1 Private Keys

- Format: PEM (PKCS#8)
- Encryption: Optional AES-256-CBC with PBKDF2
- Header: `-----BEGIN PRIVATE KEY-----` or `-----BEGIN ENCRYPTED PRIVATE KEY-----`

### 3.2 Certificates

- Format: PEM (X.509)
- Header: `-----BEGIN CERTIFICATE-----`

### 3.3 Certificate Revocation Lists

- Format: PEM and DER
- Header: `-----BEGIN X509 CRL-----`

## See Also

- [Post-Quantum](../getting-started/POST-QUANTUM.md) - Introduction to PQC algorithms
- [Hybrid Certificates](../migration/HYBRID.md) - Hybrid certificate formats
- [Compliance](../quality/COMPLIANCE.md) - Detailed compliance matrices
- [CLI Reference](CLI.md) - Command reference
