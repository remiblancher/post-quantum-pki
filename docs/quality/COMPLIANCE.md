---
title: "Standards Compliance"
description: "Conformité QPKI aux standards FIPS et RFC."
---

# Conformité Standards

Ce document présente la conformité de QPKI aux standards cryptographiques et PKI.

## Standards Cryptographiques

### FIPS 203 - ML-KEM (Key Encapsulation)

| Paramètre | Support | Usage |
|-----------|:-------:|-------|
| ML-KEM-512 | Oui | CMS EnvelopedData |
| ML-KEM-768 | Oui | CMS EnvelopedData (recommandé) |
| ML-KEM-1024 | Oui | CMS EnvelopedData |

### FIPS 204 - ML-DSA (Signatures)

| Paramètre | Support | Usage |
|-----------|:-------:|-------|
| ML-DSA-44 | Oui | Signatures (128-bit) |
| ML-DSA-65 | Oui | Signatures (recommandé, 192-bit) |
| ML-DSA-87 | Oui | Signatures (256-bit) |

### FIPS 205 - SLH-DSA (Stateless Hash-Based Signatures)

| Paramètre | Support | Usage |
|-----------|:-------:|-------|
| SLH-DSA-SHA2-128f | Oui | Signatures rapides |
| SLH-DSA-SHA2-128s | Oui | Signatures compactes |
| SLH-DSA-SHA2-192f | Oui | Signatures rapides |
| SLH-DSA-SHA2-192s | Oui | Signatures compactes |
| SLH-DSA-SHA2-256f | Oui | Signatures rapides |
| SLH-DSA-SHA2-256s | Oui | Signatures compactes |
| SLH-DSA-SHAKE-* | Oui | Variantes SHAKE |

## Standards PKI

### RFC 5280 - X.509 Certificates

| Feature | Support | Notes |
|---------|:-------:|-------|
| Certificate v3 | Oui | Extensions standard |
| CRL v2 | Oui | Delta CRL supporté |
| Basic Constraints | Oui | CA/End-entity |
| Key Usage | Oui | digitalSignature, keyEncipherment, etc. |
| Extended Key Usage | Oui | serverAuth, clientAuth, codeSigning, etc. |
| Subject Alt Name | Oui | DNS, IP, Email, URI |
| Authority Key Identifier | Oui | |
| Subject Key Identifier | Oui | |
| CRL Distribution Points | Oui | |
| Authority Information Access | Oui | OCSP, CA Issuers |

### RFC 5652 - CMS (Cryptographic Message Syntax)

| Feature | Support | Notes |
|---------|:-------:|-------|
| SignedData | Oui | EC, RSA, ML-DSA, SLH-DSA |
| EnvelopedData | Oui | RSA, ECDH, ML-KEM |
| AuthEnvelopedData | Oui | AES-GCM |
| Multiple signers | Oui | |
| Multiple recipients | Oui | |

### RFC 6960 - OCSP

| Feature | Support | Notes |
|---------|:-------:|-------|
| Basic OCSP | Oui | GET et POST |
| Nonce extension | Oui | |
| Signed response | Oui | EC, ML-DSA |
| Delegated responder | Oui | |

### RFC 3161 - TSA (Time-Stamp Protocol)

| Feature | Support | Notes |
|---------|:-------:|-------|
| TimeStampReq | Oui | |
| TimeStampResp | Oui | |
| Accuracy | Oui | Configurable |
| Ordering | Oui | |
| Nonce | Oui | |

## Algorithmes Hybrides

### Catalyst (ECDSA + ML-DSA)

Format propriétaire combinant signatures classiques et post-quantiques.

| Combinaison | Support | OID |
|-------------|:-------:|-----|
| ECDSA-P256 + ML-DSA-44 | Oui | 1.3.6.1.4.1.XXXXX.1.1 |
| ECDSA-P384 + ML-DSA-65 | Oui | 1.3.6.1.4.1.XXXXX.1.2 |
| ECDSA-P384 + ML-DSA-87 | Oui | 1.3.6.1.4.1.XXXXX.1.3 |

### Composite (IETF draft-ounsworth-pq-composite-sigs)

| Combinaison | Support | Draft |
|-------------|:-------:|-------|
| ECDSA-P256 + ML-DSA-44 | Oui | draft-13 |
| ECDSA-P384 + ML-DSA-65 | Oui | draft-13 |
| Ed25519 + ML-DSA-44 | Oui | draft-13 |

## Interopérabilité

| Validateur | Version | Statut |
|------------|---------|--------|
| OpenSSL | 3.6+ | Partiel (PQC natif, pas Composite) |
| BouncyCastle | 1.83+ | Partiel (draft-07 pour Composite) |

Voir [TESTS-INTEROP.md](TESTS-INTEROP.md) pour les détails des tests.

## Voir aussi

- [STRATEGY.md](STRATEGY.md) - Philosophie de test
- [TESTS-ACCEPTANCE.md](TESTS-ACCEPTANCE.md) - Tests d'acceptance
- [TESTS-INTEROP.md](TESTS-INTEROP.md) - Tests d'interopérabilité
