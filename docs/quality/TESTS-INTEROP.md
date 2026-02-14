---
title: "Interoperability Tests"
description: "Plan des tests d'interopérabilité QPKI - validation croisée OpenSSL et BouncyCastle."
---

# Tests d'Interopérabilité QPKI

Ce document présente le plan des tests d'interopérabilité. Ces tests valident que les artefacts générés par QPKI sont lisibles par des implémentations externes (OpenSSL, BouncyCastle).

## Vue d'ensemble

| Métrique | Valeur |
|----------|--------|
| **Validateurs** | 2 (OpenSSL 3.6+, BouncyCastle 1.83+) |
| **Tests OpenSSL** | 7 scripts |
| **Tests BouncyCastle** | 13 classes Java |
| **Artefacts testés** | Cert, CRL, CSR, CMS, OCSP, TSA |
| **Emplacement** | `test/crossval/` |

### Exécution

```bash
# Tous les tests interop
make crosstest

# OpenSSL seulement
make crosstest-openssl

# BouncyCastle seulement (nécessite Java 17+ et Maven)
make crosstest-bc

# Générer les fixtures avant les tests
make crosstest-fixtures
```

---

## Matrice de couverture

| Artefact | OpenSSL | BouncyCastle | Algorithmes testés |
|----------|:-------:|:------------:|-------------------|
| **Certificate** | TC-C-OSL-CERT | TC-C-BC-CERT | EC, RSA, ML-DSA, SLH-DSA, Catalyst, Composite |
| **CRL** | TC-C-OSL-CRL | TC-C-BC-CRL | EC, ML-DSA, Catalyst, Composite |
| **CSR** | TC-C-OSL-CSR | TC-C-BC-CSR | EC, ML-DSA |
| **CMS SignedData** | TC-C-OSL-CMS | TC-C-BC-CMS | EC, ML-DSA, SLH-DSA |
| **CMS EnvelopedData** | TC-C-OSL-CMSENC | TC-C-BC-CMSENC | RSA, ECDH, ML-KEM |
| **OCSP Response** | TC-C-OSL-OCSP | TC-C-BC-OCSP | EC, ML-DSA |
| **TSA Timestamp** | TC-C-OSL-TSA | TC-C-BC-TSA | EC, ML-DSA |
| **Extensions** | - | TC-C-BC-EXT | Custom X.509 extensions |

---

## 1. Tests OpenSSL (`test/crossval/openssl/`)

**Prérequis** : OpenSSL 3.6+ avec support PQC natif

### Scripts de validation

| Script | TC-ID | Description | Commande OpenSSL |
|--------|-------|-------------|------------------|
| `verify_certs.sh` | TC-C-OSL-CERT-001/002 | Vérifie certificats EC et PQC | `openssl verify` |
| `verify_crl.sh` | TC-C-OSL-CRL-001 | Vérifie CRL | `openssl crl -verify` |
| `verify_csr.sh` | TC-C-OSL-CSR-001 | Vérifie signature CSR | `openssl req -verify` |
| `verify_cms.sh` | TC-C-OSL-CMS-001 | Vérifie CMS SignedData | `openssl cms -verify` |
| `verify_cms_encrypt.sh` | TC-C-OSL-CMSENC-001 | Déchiffre CMS EnvelopedData | `openssl cms -decrypt` |
| `verify_ocsp.sh` | TC-C-OSL-OCSP-001 | Vérifie réponse OCSP | `openssl ocsp -verify` |
| `verify_tsa.sh` | TC-C-OSL-TSA-001 | Vérifie timestamp token | `openssl ts -verify` |

### Détail des tests OpenSSL

| TC-ID | Nom | Algorithmes | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-C-OSL-CERT-001 | Certificat ECDSA | P-256, P-384 | `OK` |
| TC-C-OSL-CERT-002 | Certificat ML-DSA | ML-DSA-44/65/87 | `OK` |
| TC-C-OSL-CRL-001 | CRL standard | EC, ML-DSA | `verify OK` |
| TC-C-OSL-CSR-001 | CSR signature | EC, ML-DSA | `verify OK` |
| TC-C-OSL-CMS-001 | CMS SignedData | EC, ML-DSA, SLH-DSA | `Verification successful` |
| TC-C-OSL-CMSENC-001 | CMS EnvelopedData | RSA, ECDH, ML-KEM | Contenu déchiffré |
| TC-C-OSL-OCSP-001 | OCSP Response | EC, ML-DSA | `Response verify OK` |
| TC-C-OSL-TSA-001 | TSA Token | EC, ML-DSA | `Verification: OK` |

### Limitations OpenSSL

| Feature | Statut | Notes |
|---------|--------|-------|
| Catalyst hybrid | Partiel | Seule signature ECDSA vérifiée, PQC ignorée |
| Composite | Non supporté | Pas de support composite dans OpenSSL |
| SLH-DSA CRL | OK | Supporté depuis OpenSSL 3.6 |

---

## 2. Tests BouncyCastle (`test/crossval/bouncycastle/`)

**Prérequis** : Java 17+, Maven 3.8+

### Classes de test Java

| Classe | TC-ID | Description |
|--------|-------|-------------|
| `ClassicalVerifyTest.java` | TC-C-BC-CERT-001 | Certificats ECDSA/RSA |
| `PQCVerifyTest.java` | TC-C-BC-CERT-002 | Certificats ML-DSA, SLH-DSA |
| `CatalystVerifyTest.java` | TC-C-BC-CERT-003 | Certificats Catalyst hybrid |
| `CompositeVerifyTest.java` | TC-C-BC-CERT-004 | Certificats Composite hybrid |
| `CRLVerifyTest.java` | TC-C-BC-CRL-001 | CRL standard |
| `CatalystCRLVerifyTest.java` | TC-C-BC-CRL-002 | CRL Catalyst |
| `CompositeCRLVerifyTest.java` | TC-C-BC-CRL-003 | CRL Composite |
| `CSRVerifyTest.java` | TC-C-BC-CSR-001 | CSR signature |
| `CMSVerifyTest.java` | TC-C-BC-CMS-001 | CMS SignedData |
| `CMSEnvelopedTest.java` | TC-C-BC-CMSENC-001 | CMS EnvelopedData/AuthEnvelopedData |
| `OCSPVerifyTest.java` | TC-C-BC-OCSP-001 | OCSP Response |
| `TSAVerifyTest.java` | TC-C-BC-TSA-001 | TSA Timestamp |
| `ExtensionsVerifyTest.java` | TC-C-BC-EXT-001 | Extensions X.509 custom |

### Détail des tests BouncyCastle

| TC-ID | Nom | Algorithmes | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-C-BC-CERT-001 | Certificat classique | ECDSA, RSA | Chaîne validée |
| TC-C-BC-CERT-002 | Certificat PQC | ML-DSA, SLH-DSA | Signature validée |
| TC-C-BC-CERT-003 | Certificat Catalyst | EC + ML-DSA | Les deux signatures validées |
| TC-C-BC-CERT-004 | Certificat Composite | ECDSA-ML-DSA | Signature composite validée |
| TC-C-BC-CRL-001 | CRL standard | EC, ML-DSA | Signature CRL validée |
| TC-C-BC-CRL-002 | CRL Catalyst | EC + ML-DSA | Les deux signatures validées |
| TC-C-BC-CRL-003 | CRL Composite | Composite | Signature composite validée |
| TC-C-BC-CSR-001 | CSR | EC, ML-DSA | Signature CSR validée |
| TC-C-BC-CMS-001 | CMS SignedData | EC, ML-DSA, SLH-DSA | SignedData validé |
| TC-C-BC-CMSENC-001 | CMS EnvelopedData | RSA, ECDH, ML-KEM | Contenu déchiffré |
| TC-C-BC-OCSP-001 | OCSP Response | EC, ML-DSA | Response validée |
| TC-C-BC-TSA-001 | TSA Token | EC, ML-DSA | Token validé |
| TC-C-BC-EXT-001 | Extensions custom | - | Extensions parsées correctement |

### Limitations BouncyCastle

| Feature | Statut | Notes |
|---------|--------|-------|
| Catalyst hybrid | OK | Support complet |
| Composite | Partiel | BC 1.83 utilise draft-07, QPKI draft-13 (OID différent) |
| ML-KEM CMS | OK | Support complet |

---

## 3. Fixtures (`test/crossval/fixtures/`)

Les fixtures sont des artefacts générés par QPKI utilisés comme entrée des tests.

### Génération

```bash
# Génère toutes les fixtures
./test/crossval/generate_qpki_fixtures.sh

# Ou via Makefile
make crosstest-fixtures
```

### Structure des fixtures

```
test/crossval/fixtures/
├── ec/                     # Artefacts EC (P-256, P-384)
│   ├── root-ca.crt
│   ├── leaf.crt
│   ├── leaf.crl
│   ├── leaf.csr
│   ├── cms-signed.p7s
│   ├── cms-encrypted.p7m
│   ├── ocsp-response.der
│   └── timestamp.tsr
│
├── ml/                     # Artefacts ML-DSA (44, 65, 87)
│   └── ...
│
├── slh/                    # Artefacts SLH-DSA
│   └── ...
│
├── hybrid/                 # Artefacts hybrides
│   ├── catalyst/
│   └── composite/
│
└── extensions/             # Tests d'extensions custom
    └── ...
```

---

## 4. CI/CD

| Job | Tests | Durée | Prérequis |
|-----|-------|-------|-----------|
| `crosstest-openssl` | TC-C-OSL-* | ~5 min | OpenSSL 3.6+ |
| `crosstest-bc` | TC-C-BC-* | ~3 min | Java 17+, Maven |

### Workflow GitHub Actions

```yaml
crosstest:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Setup OpenSSL 3.6
      run: |
        # Install OpenSSL with PQC support

    - name: Setup Java 17
      uses: actions/setup-java@v4
      with:
        java-version: '17'

    - name: Generate fixtures
      run: make crosstest-fixtures

    - name: Run OpenSSL tests
      run: make crosstest-openssl

    - name: Run BouncyCastle tests
      run: make crosstest-bc
```

---

## 5. Dépannage

### OpenSSL ne reconnaît pas ML-DSA

```bash
# Vérifier la version
openssl version
# Doit être >= 3.6.0

# Vérifier les algorithmes PQC
openssl list -signature-algorithms | grep -i ml
```

### BouncyCastle : OID mismatch pour Composite

BC 1.83 utilise les OIDs draft-07 (`2.16.840.1.114027.80.8.1.x`), QPKI utilise draft-13 (`1.3.6.1.5.5.7.6.x`).

Workaround : Attendre BC 1.84+ ou tester uniquement Catalyst.

### Fixtures manquantes

```bash
# Régénérer les fixtures
make crosstest-fixtures

# Vérifier le contenu
ls -la test/crossval/fixtures/
```

---

## Voir aussi

- [TESTS-ACCEPTANCE.md](TESTS-ACCEPTANCE.md) - Tests d'acceptance CLI
- [COMPLIANCE.md](COMPLIANCE.md) - Conformité standards
- [STRATEGY.md](STRATEGY.md) - Stratégie de test
