---
title: "Test Catalog"
description: "Exhaustive list of QPKI test cases following ISO/IEC 29119-3."
generated: true
---

# QPKI Test Catalog

> **Note**: This file is auto-generated from `specs/tests/test-catalog.yaml`.
> Do not edit manually. Run `make quality-docs` to regenerate.

This catalog documents all test cases following ISO/IEC 29119-3 Test Documentation standard.

## TC-ID Format

```
TC-<TYPE>-<DOMAIN>-<SEQ>

TYPE:   U (Unit), F (Functional), A (Acceptance), C (Crossval), Z (fuZz)
DOMAIN: KEY, CA, CERT, CRL, OCSP, TSA, CMS, HSM
SEQ:    001-999
```

## Summary

| Metric | Value |
|--------|-------|
| Test Types | 5 (U, F, A, C, Z) |
| Domains | 8 |
| Last Updated | 2026-02-11 |

---

## Unit Tests (TC-U-*)

Unit tests validate individual functions in isolation.

### TC-U-KEY - Key Generation

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-U-KEY-001 | ECDSA P-256 key generation | `TestU_Key_Generate_ECDSA_P256` | FIPS 186-5 |
| TC-U-KEY-002 | ECDSA P-384 key generation | `TestU_Key_Generate_ECDSA_P384` | FIPS 186-5 |
| TC-U-KEY-003 | ML-DSA-44 key generation | `TestU_Key_Generate_MLDSA44` | FIPS 204 |
| TC-U-KEY-004 | ML-DSA-65 key generation | `TestU_Key_Generate_MLDSA65` | FIPS 204 |
| TC-U-KEY-005 | ML-DSA-87 key generation | `TestU_Key_Generate_MLDSA87` | FIPS 204 |
| TC-U-KEY-006 | SLH-DSA-128f key generation | `TestU_Key_Generate_SLHDSA` | FIPS 205 |
| TC-U-KEY-007 | ML-KEM-768 key generation | `TestU_Key_Generate_MLKEM768` | FIPS 203 |

---

## Functional Tests (TC-F-*)

Functional tests validate internal workflows and APIs.

### TC-F-CA - Certificate Authority

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CA-001 | ECDSA CA initialization | `TestF_CA_Initialize_ECDSA` | RFC 5280 |
| TC-F-CA-002 | ML-DSA-65 CA initialization | `TestF_CA_Initialize_MLDSA65` | RFC 5280, FIPS 204 |
| TC-F-CA-003 | Catalyst hybrid CA | `TestF_CA_Initialize_Catalyst` | ITU-T X.509 9.8 |
| TC-F-CA-004 | Composite hybrid CA | `TestF_CA_Initialize_Composite` | IETF draft-13 |

### TC-F-CERT - Certificate Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CERT-001 | ECDSA certificate from CSR | `TestF_Cert_Issue_ECDSA` | RFC 5280, RFC 2986 |
| TC-F-CERT-002 | ML-DSA certificate issuance | `TestF_Cert_Issue_MLDSA` | RFC 5280, FIPS 204 |
| TC-F-CERT-003 | ML-KEM certificate | `TestF_Cert_Issue_MLKEM` | RFC 9883 |

### TC-F-CRL - CRL Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CRL-001 | ECDSA CRL generation | `TestF_CRL_Generate_ECDSA` | RFC 5280 |
| TC-F-CRL-002 | ML-DSA CRL generation | `TestF_CRL_Generate_MLDSA` | RFC 5280, FIPS 204 |

### TC-F-OCSP - OCSP Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-OCSP-001 | ECDSA OCSP response | `TestF_OCSP_Response_ECDSA` | RFC 6960 |
| TC-F-OCSP-002 | ML-DSA OCSP response | `TestF_OCSP_Response_MLDSA` | RFC 6960, FIPS 204 |

### TC-F-TSA - TSA Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-TSA-001 | ECDSA timestamp | `TestF_TSA_Timestamp_ECDSA` | RFC 3161 |
| TC-F-TSA-002 | ML-DSA timestamp | `TestF_TSA_Timestamp_MLDSA` | RFC 3161, FIPS 204 |

### TC-F-CMS - CMS Operations

| ID | Name | Go Test | Requirement |
|----|------|---------|-------------|
| TC-F-CMS-001 | ECDSA CMS SignedData | `TestF_CMS_Sign_ECDSA` | RFC 5652 |
| TC-F-CMS-002 | ML-DSA CMS SignedData | `TestF_CMS_Sign_MLDSA` | RFC 5652, RFC 9882 |
| TC-F-CMS-003 | ML-KEM CMS EnvelopedData | `TestF_CMS_Encrypt_MLKEM` | RFC 5652, FIPS 203 |

---

## Acceptance Tests (TC-A-*)

Acceptance tests validate CLI commands end-to-end (black box).

**Location**: `test/acceptance/`

| ID | Name | Go Test | Command |
|----|------|---------|---------|
| TC-A-CA-001 | CA init with profile | `TestA_CA_Init_WithProfile` | `qpki ca init` |
| TC-A-CA-002 | CA init with HSM | `TestA_CA_Init_WithHSM` | `qpki ca init --hsm` |
| TC-A-CERT-001 | Certificate from CSR | `TestA_Cert_Issue_FromCSR` | `qpki cert issue` |
| TC-A-CMS-001 | CMS sign ML-DSA | `TestA_CMS_Sign_MLDSA` | `qpki cms sign` |

> **Note**: See [CLI-COVERAGE.md](CLI-COVERAGE.md) for complete CLI test coverage.

---

## Cross-Validation Tests (TC-C-*)

Cross-validation tests verify interoperability with external implementations.

**Location**: `test/bouncycastle/`, `test/openssl/`

### TC-C-OSL - OpenSSL 3.6+

| ID | Name | Validator | Artifact |
|----|------|-----------|----------|
| TC-C-OSL-001 | Verify ECDSA certificate | OpenSSL | Certificate |
| TC-C-OSL-002 | Verify ML-DSA certificate | OpenSSL | Certificate |
| TC-C-OSL-003 | Verify ML-DSA CMS | OpenSSL | CMS SignedData |
| TC-C-OSL-004 | Decrypt ML-KEM CMS | OpenSSL | CMS EnvelopedData |

### TC-C-BC - BouncyCastle 1.83+

| ID | Name | Validator | Artifact |
|----|------|-----------|----------|
| TC-C-BC-001 | Verify ECDSA certificate | BouncyCastle | Certificate |
| TC-C-BC-002 | Verify ML-DSA certificate | BouncyCastle | Certificate |
| TC-C-BC-003 | Verify Catalyst certificate | BouncyCastle | Certificate |
| TC-C-BC-004 | Verify Composite certificate | BouncyCastle | Certificate |

---

## Fuzzing Tests (TC-Z-*)

Fuzzing tests ensure parsers handle malformed input without panicking.

| ID | Name | Go Test | File |
|----|------|---------|------|
| TC-Z-CMS-001 | CMS parser fuzzing | `FuzzCMSParser` | internal/cms/fuzz_test.go |
| TC-Z-OCSP-001 | OCSP request fuzzing | `FuzzOCSPRequest` | internal/ocsp/fuzz_test.go |
| TC-Z-PROFILE-001 | Profile YAML fuzzing | `FuzzProfileParser` | internal/profile/fuzz_test.go |
| TC-Z-CSR-001 | PQC CSR fuzzing | `FuzzCSRParser` | internal/x509util/fuzz_test.go |

---

## Priority Definitions

| Priority | Description | CI Blocking |
|----------|-------------|-------------|
| P1 | Critical - Must pass for release | true |
| P2 | High - Should pass, may have known limitations | false |
| P3 | Medium - Nice to have | false |

## See Also

- [Test Strategy](STRATEGY.md) - Testing philosophy
- [Test Naming](NAMING.md) - Naming conventions
- [CLI Coverage](CLI-COVERAGE.md) - CLI command coverage
- [Feature Coverage](FEATURES.md) - Feature coverage
- [specs/tests/test-mapping.yaml](../../../specs/tests/test-mapping.yaml) - TC-ID mapping
