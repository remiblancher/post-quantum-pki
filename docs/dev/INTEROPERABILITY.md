# Interoperability Matrix

This document details the cross-validation testing between QPKI and external implementations.

## 1. External Validators

| Tool | Version | Capabilities |
|------|---------|--------------|
| **OpenSSL** | 3.6+ | Native PQC (ML-DSA, SLH-DSA, ML-KEM), classical algorithms |
| **BouncyCastle** | 1.83+ | Full PQC support, Catalyst extensions, Composite (draft-07) |

## 2. Test Case Naming Convention

Format: `TC-<CATEGORY>-<ALGO>-<NUM>`

### Categories

| Prefix | Category | Description |
|--------|----------|-------------|
| `TC-CERT` | Certificates | X.509 certificate operations |
| `TC-CSR` | CSR | Certificate Signing Requests |
| `TC-CRL` | CRL | Certificate Revocation Lists |
| `TC-OCSP` | OCSP | Online Certificate Status Protocol |
| `TC-TSA` | TSA | Timestamping Authority |
| `TC-CMS` | CMS | Cryptographic Message Syntax |
| `TC-XOSL` | Cross-OpenSSL | OpenSSL verification tests |
| `TC-XBC` | Cross-BC | BouncyCastle verification tests |
| `TC-FUZZ` | Fuzzing | Parser robustness tests |

### Algorithm Suffixes

| Suffix | Algorithm |
|--------|-----------|
| `-EC` | ECDSA (P-256, P-384, P-521) |
| `-RSA` | RSA (2048, 4096) |
| `-ED` | Ed25519 |
| `-ML` | ML-DSA (44, 65, 87) |
| `-SLH` | SLH-DSA (128f, 192f, 256f) |
| `-KEM` | ML-KEM (512, 768, 1024) |
| `-CAT` | Catalyst hybrid |
| `-COMP` | Composite hybrid |

### Examples

```
TC-CERT-EC-001      EC certificate issuance
TC-CERT-ML-001      ML-DSA certificate issuance
TC-CERT-CAT-001     Catalyst hybrid certificate
TC-XOSL-ML-001      OpenSSL verification of ML-DSA
TC-XBC-CAT-001      BouncyCastle verification of Catalyst
TC-FUZZ-CMS-001     CMS parser fuzzing
```

## 3. Algorithm x Operation Matrix

| Operation | EC | RSA | Ed25519 | ML-DSA | SLH-DSA | ML-KEM | Catalyst | Composite |
|-----------|:--:|:---:|:-------:|:------:|:-------:|:------:|:--------:|:---------:|
| Key Gen | TC-KEY-EC | TC-KEY-RSA | TC-KEY-ED | TC-KEY-ML | TC-KEY-SLH | TC-KEY-KEM | TC-KEY-CAT | TC-KEY-COMP |
| CA Init | TC-CA-EC | TC-CA-RSA | - | TC-CA-ML | TC-CA-SLH | - | TC-CA-CAT | TC-CA-COMP |
| Cert Issue | TC-CERT-EC | TC-CERT-RSA | - | TC-CERT-ML | TC-CERT-SLH | TC-CERT-KEM* | TC-CERT-CAT | TC-CERT-COMP |
| CSR Gen | TC-CSR-EC | TC-CSR-RSA | TC-CSR-ED | TC-CSR-ML | TC-CSR-SLH | TC-CSR-KEM | TC-CSR-CAT | TC-CSR-COMP |
| CRL Gen | TC-CRL-EC | TC-CRL-RSA | - | TC-CRL-ML | TC-CRL-SLH | - | TC-CRL-CAT | TC-CRL-COMP |
| OCSP | TC-OCSP-EC | TC-OCSP-RSA | - | TC-OCSP-ML | TC-OCSP-SLH | - | TC-OCSP-CAT | TC-OCSP-COMP |
| TSA | TC-TSA-EC | TC-TSA-RSA | - | TC-TSA-ML | TC-TSA-SLH | - | TC-TSA-CAT | TC-TSA-COMP |
| CMS Sign | TC-CMS-EC | TC-CMS-RSA | - | TC-CMS-ML | TC-CMS-SLH | - | TC-CMS-CAT | TC-CMS-COMP |
| CMS Encrypt | - | TC-CMS-RSA-ENC | - | - | - | TC-CMS-KEM-ENC | - | - |

*ML-KEM certificates require RFC 9883 attestation

## 4. Cross-Validation Matrix

### Certificates

| Type | QPKI | OpenSSL 3.6 | BouncyCastle 1.83 |
|------|:----:|:-----------:|:-----------------:|
| ECDSA (P-256/384/521) | TC-CERT-EC | TC-XOSL-EC | TC-XBC-EC |
| RSA (2048/4096) | TC-CERT-RSA | TC-XOSL-RSA | TC-XBC-RSA |
| Ed25519 | TC-CERT-ED | TC-XOSL-ED | TC-XBC-ED |
| ML-DSA-44/65/87 | TC-CERT-ML | TC-XOSL-ML | TC-XBC-ML |
| SLH-DSA-* | TC-CERT-SLH | TC-XOSL-SLH | TC-XBC-SLH |
| Catalyst | TC-CERT-CAT | TC-XOSL-CAT* | TC-XBC-CAT |
| Composite | TC-CERT-COMP | N/A | TC-XBC-COMP** |

### CSR

| Type | QPKI | OpenSSL 3.6 | BouncyCastle 1.83 |
|------|:----:|:-----------:|:-----------------:|
| Classical | TC-CSR-EC/RSA | TC-XOSL-CSR | TC-XBC-CSR |
| PQC (ML-DSA) | TC-CSR-ML | TC-XOSL-CSR-ML | TC-XBC-CSR-ML |
| ML-KEM (RFC 9883) | TC-CSR-KEM | TC-XOSL-CSR-KEM | TC-XBC-CSR-KEM |
| Hybrid | TC-CSR-CAT | TC-XOSL-CSR-CAT | TC-XBC-CSR-CAT |

### CRL

| Type | QPKI | OpenSSL 3.6 | BouncyCastle 1.83 |
|------|:----:|:-----------:|:-----------------:|
| Classical | TC-CRL-EC/RSA | TC-XOSL-CRL | TC-XBC-CRL |
| PQC | TC-CRL-ML/SLH | TC-XOSL-CRL-ML | TC-XBC-CRL-ML |
| Catalyst | TC-CRL-CAT | TC-XOSL-CRL-CAT* | TC-XBC-CRL-CAT |
| Composite | TC-CRL-COMP | N/A | TC-XBC-CRL-COMP** |

### Protocols (OCSP, TSA, CMS)

| Protocol | QPKI | OpenSSL 3.6 | BouncyCastle 1.83 |
|----------|:----:|:-----------:|:-----------------:|
| OCSP Response | TC-OCSP-* | TC-XOSL-OCSP | TC-XBC-OCSP |
| TSA Token | TC-TSA-* | TC-XOSL-TSA | TC-XBC-TSA |
| CMS Signed | TC-CMS-* | TC-XOSL-CMS | TC-XBC-CMS |
| CMS Encrypted | TC-CMS-*-ENC | N/A | TC-XBC-CMS-ENC |

**Legend:**
- `*` OpenSSL verifies classical signature only (PQC signature ignored)
- `**` BouncyCastle parses but uses draft-07 OIDs (signature verification requires OID alignment)
- `N/A` Not supported by external validator

## 5. Known Limitations

| Feature | Status | Details |
|---------|--------|---------|
| **Composite signatures** | Partial | BC 1.83 uses draft-07 OIDs (`2.16.840.1.114027.80.8.1.x`), QPKI uses draft-13 (`1.3.6.1.5.5.7.6.x`) |
| **Catalyst in OpenSSL** | Partial | Only ECDSA signature verified, PQC alternative signature ignored |
| **CMS Encryption OpenSSL** | Not supported | OpenSSL 3.6 does not support ML-KEM in CMS |

## 6. CI Job Reference

| CI Job | Test Cases | Scripts/Classes | Duration |
|--------|------------|-----------------|----------|
| `test` | TC-UNIT-*, TC-INT-* | `*_test.go` | ~15 min |
| `pki-test` | TC-CA-*, TC-CERT-*, TC-KEY-*, TC-CSR-*, TC-CRL-*, TC-CRED-* | CI workflow steps | ~15 min |
| `ocsp-test` | TC-OCSP-* | CI workflow steps | ~15 min |
| `tsa-test` | TC-TSA-* | CI workflow steps | ~15 min |
| `cms-test` | TC-CMS-* | CI workflow steps | ~15 min |
| `crosstest-openssl` | TC-XOSL-* | `test/openssl/verify_*.sh` | ~30 min |
| `crosstest-bc` | TC-XBC-* | `test/bouncycastle/src/test/java/*Test.java` | ~15 min |
| `hsm-test` | TC-HSM-* | CI workflow steps (SoftHSM2) | ~15 min |
| `cryptoagility-test` | TC-AGIL-* | CI workflow steps | ~30 min |
| `fuzz` | TC-FUZZ-* | `*_fuzz_test.go` | ~30 min |
| `security` | TC-SEC-* | Trivy scanner | ~10 min |

## 7. OpenSSL Cross-Test Scripts

| Script | Tests |
|--------|-------|
| `verify_classical.sh` | ECDSA, RSA certificate verification |
| `verify_pqc.sh` | ML-DSA, SLH-DSA certificate verification |
| `verify_catalyst.sh` | Catalyst hybrid (classical signature only) |
| `verify_certs.sh` | General certificate structure |
| `verify_csr.sh` | CSR validation |
| `verify_crl.sh` | CRL validation |
| `verify_extension_variants.sh` | X.509 extension edge cases |
| `verify_ocsp.sh` | OCSP response validation |
| `verify_tsa.sh` | Timestamp response validation |
| `verify_cms.sh` | CMS signed data validation |
| `verify_cms_encrypt.sh` | CMS encryption (RSA only) |

## 8. BouncyCastle Cross-Test Classes

| Class | Tests |
|-------|-------|
| `ClassicalVerifyTest.java` | ECDSA, RSA verification |
| `PQCVerifyTest.java` | ML-DSA, SLH-DSA verification |
| `CatalystVerifyTest.java` | Catalyst hybrid (both signatures) |
| `CompositeVerifyTest.java` | Composite hybrid (parsing) |
| `CRLVerifyTest.java` | CRL verification |
| `OCSPVerifyTest.java` | OCSP response verification |
| `TSAVerifyTest.java` | Timestamp verification |
| `CMSVerifyTest.java` | CMS signed data verification |
| `ExtensionsVerifyTest.java` | X.509 extension parsing |

## 9. See Also

- [TESTING.md](TESTING.md) - Testing strategy and local execution
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development workflow
