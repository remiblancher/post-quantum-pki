---
title: "SSH Cross-Tests"
description: "Plan des tests de validation croisée SSH — certificats OpenSSH générés par QPKI."
---

# Tests SSH (Cross-validation OpenSSH)

Ce document présente le plan des tests de validation croisée SSH. Ces tests valident que les certificats SSH générés par QPKI sont compatibles avec les outils OpenSSH natifs (`ssh-keygen`, `sshd`).

> **Note** : BouncyCastle ne supporte **pas** le format de certificat OpenSSH. Les cross-tests SSH utilisent exclusivement les outils OpenSSH.

## Vue d'ensemble

| Métrique | Valeur |
|----------|--------|
| **Validateur** | OpenSSH (ssh-keygen, sshd) |
| **Tests** | 13 cas de test |
| **Artefacts testés** | User cert, Host cert, KRL |
| **Algorithmes** | Ed25519, ECDSA-P256, RSA-4096 |
| **Emplacement** | `test/crossval/ssh/` |

### Exécution

```bash
# Tous les tests SSH
make crosstest-ssh

# Générer les fixtures SSH
make crosstest-ssh-fixtures
```

---

## Matrice de couverture

| Artefact | TC-ID Prefix | Algorithmes testés | Outil de validation |
|----------|:------------:|-------------------|---------------------|
| **User Certificate** | TC-XSSH-UCERT | Ed25519, ECDSA-P256, RSA-4096 | `ssh-keygen -L` |
| **Host Certificate** | TC-XSSH-HCERT | Ed25519, ECDSA-P256, RSA-4096 | `ssh-keygen -L` |
| **User Auth E2E** | TC-XSSH-AUTH | Ed25519 | `sshd` + `ssh` |
| **Principals** | TC-XSSH-PRINC | Ed25519 | `ssh-keygen -L`, `sshd` |
| **Validity** | TC-XSSH-VALID | Ed25519 | `ssh-keygen -L`, `sshd` |
| **Extensions** | TC-XSSH-EXT | Ed25519 | `ssh-keygen -L` |
| **KRL** | TC-XSSH-KRL | Ed25519 | `ssh-keygen -Q` |

---

## 1. Scripts de validation (`test/crossval/ssh/`)

### Structure

```
test/crossval/ssh/
├── run_all.sh                    # Orchestrateur
├── lib/
│   ├── verify_user_cert.sh       # TC-XSSH-UCERT-*
│   ├── verify_host_cert.sh       # TC-XSSH-HCERT-*
│   ├── verify_auth.sh            # TC-XSSH-AUTH-*
│   ├── verify_principals.sh      # TC-XSSH-PRINC-*
│   ├── verify_validity.sh        # TC-XSSH-VALID-*
│   ├── verify_extensions.sh      # TC-XSSH-EXT-*
│   └── verify_krl.sh             # TC-XSSH-KRL-*
└── results/
    ├── results-ssh.json          # Résultats JSON
    └── ctrf-crosstest-ssh.json   # Export CTRF pour CI
```

### Scripts

| Script | TC-IDs | Description | Commande |
|--------|--------|-------------|----------|
| `verify_user_cert.sh` | TC-XSSH-UCERT-* | Vérifie structure certificat user | `ssh-keygen -L` |
| `verify_host_cert.sh` | TC-XSSH-HCERT-* | Vérifie structure certificat host | `ssh-keygen -L` |
| `verify_auth.sh` | TC-XSSH-AUTH-* | Authentification E2E avec sshd | `sshd` + `ssh` |
| `verify_principals.sh` | TC-XSSH-PRINC-* | Validation des principals | `ssh-keygen -L`, `sshd` |
| `verify_validity.sh` | TC-XSSH-VALID-* | Fenêtre de validité, rejet expiré | `ssh-keygen -L`, `sshd` |
| `verify_extensions.sh` | TC-XSSH-EXT-* | Critical options, permissions | `ssh-keygen -L` |
| `verify_krl.sh` | TC-XSSH-KRL-* | Révocation via KRL | `ssh-keygen -Q` |

---

## 2. Détail des tests

### Certificats User

| TC-ID | Nom | Algorithme | Résultat attendu |
|-------|-----|------------|------------------|
| TC-XSSH-UCERT-ED25519 | User cert Ed25519 | Ed25519 | `ssh-keygen -L` OK, type `user certificate` |
| TC-XSSH-UCERT-ECDSA | User cert ECDSA | ECDSA-P256 | `ssh-keygen -L` OK, type `user certificate` |
| TC-XSSH-UCERT-RSA | User cert RSA | RSA-4096 | `ssh-keygen -L` OK, type `user certificate` |

### Certificats Host

| TC-ID | Nom | Algorithme | Résultat attendu |
|-------|-----|------------|------------------|
| TC-XSSH-HCERT-ED25519 | Host cert Ed25519 | Ed25519 | `ssh-keygen -L` OK, type `host certificate` |
| TC-XSSH-HCERT-ECDSA | Host cert ECDSA | ECDSA-P256 | `ssh-keygen -L` OK, type `host certificate` |
| TC-XSSH-HCERT-RSA | Host cert RSA | RSA-4096 | `ssh-keygen -L` OK, type `host certificate` |

### Authentification E2E

| TC-ID | Nom | Description | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-XSSH-AUTH-ED25519 | Auth E2E Ed25519 | sshd accepte le certificat user | Connexion SSH réussie |

### Principals

| TC-ID | Nom | Description | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-XSSH-PRINC-OK | Principals match | Principal listé dans le cert | Authentification acceptée |
| TC-XSSH-PRINC-DENY | Principals reject | Principal non listé | Authentification refusée |

### Validité

| TC-ID | Nom | Description | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-XSSH-VALID | Fenêtre de validité | Dates Valid After/Before correctes | `ssh-keygen -L` affiche les dates |
| TC-XSSH-EXPIRED | Cert expiré rejeté | Certificat avec validité passée | sshd refuse le certificat |

### Extensions et Critical Options

| TC-ID | Nom | Description | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-XSSH-EXT-FC | Force-command | Critical option `force-command` | `ssh-keygen -L` affiche la restriction |
| TC-XSSH-EXT-SA | Source-address | Critical option `source-address` | `ssh-keygen -L` affiche la restriction IP |
| TC-XSSH-EXT-PTY | Permit-pty | Extension `permit-pty` | `ssh-keygen -L` affiche la permission |

### KRL (Key Revocation Lists)

| TC-ID | Nom | Description | Résultat attendu |
|-------|-----|-------------|------------------|
| TC-XSSH-KRL-CHK | Cert révoqué détecté | Certificat révoqué dans KRL | `ssh-keygen -Q` indique révoqué |
| TC-XSSH-KRL-PASS | Cert non révoqué passe | Certificat absent de la KRL | `ssh-keygen -Q` indique OK |
| TC-XSSH-KRL-SER | Révocation par serial | Cert révoqué par numéro de série | `ssh-keygen -Q` indique révoqué |

---

## 3. Fixtures (`test/crossval/fixtures/ssh/`)

Les fixtures sont des artefacts SSH générés par QPKI utilisés comme entrée des tests.

### Génération

```bash
# Génère toutes les fixtures SSH
./test/crossval/generate_qpki_ssh_fixtures.sh

# Ou via Makefile
make crosstest-ssh-fixtures
```

### Structure des fixtures

```
test/crossval/fixtures/ssh/
├── user-ca/                    # CA user par algorithme
│   ├── ed25519/
│   │   ├── ssh-ca.pub
│   │   └── ssh-ca.key
│   ├── ecdsa-p256/
│   └── rsa-4096/
│
├── host-ca/                    # CA host par algorithme
│   ├── ed25519/
│   ├── ecdsa-p256/
│   └── rsa-4096/
│
├── user-certs/                 # Certificats user émis
│   ├── ed25519-cert.pub
│   ├── ecdsa-p256-cert.pub
│   └── rsa-4096-cert.pub
│
├── host-certs/                 # Certificats host émis
│   ├── ed25519-cert.pub
│   ├── ecdsa-p256-cert.pub
│   └── rsa-4096-cert.pub
│
└── krl/                        # KRL générées
    └── revoked.krl
```

---

## 4. CI/CD

| Job | Tests | Durée estimée | Prérequis |
|-----|-------|---------------|-----------|
| `crosstest-ssh` | TC-XSSH-* | ~5 min | OpenSSH (préinstallé) |

### Job GitHub Actions

```yaml
crosstest-ssh:
  name: "[Interop] OpenSSH Certificates"
  runs-on: ubuntu-latest
  timeout-minutes: 15
  needs: [build]
  steps:
    - uses: actions/checkout@v6

    - name: Download binary
      uses: actions/download-artifact@v8
      with:
        name: qpki-ci-binary
        path: ./

    - name: Make executable
      run: chmod +x ./qpki

    - name: "[SSH] Verify OpenSSH Version"
      run: ssh -V

    - name: "[SSH] Generate SSH Fixtures"
      run: |
        chmod +x test/crossval/generate_qpki_ssh_fixtures.sh
        ./test/crossval/generate_qpki_ssh_fixtures.sh

    - name: "[SSH] Run SSH Cross-Tests"
      run: |
        cd test/crossval/ssh
        chmod +x run_all.sh
        ./run_all.sh

    - name: "[SSH] Upload Results"
      if: always()
      uses: actions/upload-artifact@v7
      with:
        name: ctrf-crosstest-ssh
        path: |
          test/crossval/ssh/results/ctrf-crosstest-ssh.json
          test/crossval/ssh/results/results-ssh.json
        retention-days: 30
```

---

## 5. Dépannage

### ssh-keygen ne peut pas lire le certificat

```bash
# Vérifier le format du fichier
file cert.pub
# Doit être "OpenSSH ... certificate"

# Tenter la lecture
ssh-keygen -L -f cert.pub
```

### sshd refuse le certificat

```bash
# Mode debug sshd
/usr/sbin/sshd -d -p 2222

# Connexion verbose
ssh -vvv -p 2222 -o CertificateFile=cert.pub user@localhost
```

### KRL non reconnue

```bash
# Vérifier le format KRL
ssh-keygen -Q -f revoked.krl cert.pub

# Si erreur "not a KRL" : le fichier n'est pas au format binaire OpenSSH KRL
```

---

## Voir aussi

- [SSH](../services/SSH.md) - Guide des certificats SSH
- [TESTS-INTEROP.md](TESTS-INTEROP.md) - Tests d'interopérabilité X.509 (OpenSSL/BouncyCastle)
- [TESTS-ACCEPTANCE.md](TESTS-ACCEPTANCE.md) - Tests d'acceptance CLI
- [STRATEGY.md](STRATEGY.md) - Stratégie de test
