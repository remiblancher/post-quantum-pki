#!/usr/bin/env bash
# generate_qpki_ssh_fixtures.sh — Generate SSH certificate fixtures for cross-testing
#
# Generates user/host CAs and certificates using qpki CLI for validation
# by OpenSSH tools (ssh-keygen -L, ssh-keygen -Q).
#
# Usage: ./generate_qpki_ssh_fixtures.sh [qpki-binary-path]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Find qpki binary
QPKI="${1:-}"
if [ -z "$QPKI" ]; then
  if [ -x "$PROJECT_ROOT/qpki" ]; then
    QPKI="$PROJECT_ROOT/qpki"
  elif command -v qpki &>/dev/null; then
    QPKI="$(command -v qpki)"
  else
    echo "Building qpki..."
    (cd "$PROJECT_ROOT" && go build -o qpki ./cmd/qpki)
    QPKI="$PROJECT_ROOT/qpki"
  fi
fi

echo "Using qpki: $QPKI"
echo "Version: $($QPKI --version 2>/dev/null || echo 'unknown')"

# Output directory
FIXTURES="$SCRIPT_DIR/fixtures/ssh"
rm -rf "$FIXTURES"
mkdir -p "$FIXTURES"/{user-ca,host-ca,user-certs,host-certs,krl,keys}

ALGORITHMS=("ed25519" "ecdsa-p256" "rsa-4096")

echo ""
echo "=== Generating SSH Fixtures ==="

# --- Generate key pairs for each algorithm ---
for alg in "${ALGORITHMS[@]}"; do
  echo "  [keys] Generating $alg user key pair..."
  case "$alg" in
    ed25519)   ssh-keygen -t ed25519 -f "$FIXTURES/keys/$alg" -N "" -q ;;
    ecdsa-p256) ssh-keygen -t ecdsa -b 256 -f "$FIXTURES/keys/$alg" -N "" -q ;;
    rsa-4096)  ssh-keygen -t rsa -b 4096 -f "$FIXTURES/keys/$alg" -N "" -q ;;
  esac
done

# Also generate host keys
for alg in "${ALGORITHMS[@]}"; do
  echo "  [keys] Generating $alg host key pair..."
  case "$alg" in
    ed25519)   ssh-keygen -t ed25519 -f "$FIXTURES/keys/host-$alg" -N "" -q ;;
    ecdsa-p256) ssh-keygen -t ecdsa -b 256 -f "$FIXTURES/keys/host-$alg" -N "" -q ;;
    rsa-4096)  ssh-keygen -t rsa -b 4096 -f "$FIXTURES/keys/host-$alg" -N "" -q ;;
  esac
done

# --- Create User CAs ---
for alg in "${ALGORITHMS[@]}"; do
  echo "  [user-ca] Initializing $alg user CA..."
  $QPKI ssh ca-init \
    --name "test-user-ca-$alg" \
    --algorithm "$alg" \
    --type user \
    --ca-dir "$FIXTURES/user-ca/$alg"
done

# --- Create Host CAs ---
for alg in "${ALGORITHMS[@]}"; do
  echo "  [host-ca] Initializing $alg host CA..."
  $QPKI ssh ca-init \
    --name "test-host-ca-$alg" \
    --algorithm "$alg" \
    --type host \
    --ca-dir "$FIXTURES/host-ca/$alg"
done

# --- Issue User Certificates ---
for alg in "${ALGORITHMS[@]}"; do
  echo "  [user-cert] Issuing $alg user certificate..."
  $QPKI ssh issue \
    --ca-dir "$FIXTURES/user-ca/$alg" \
    --public-key "$FIXTURES/keys/$alg.pub" \
    --key-id "testuser-$alg@crosstest" \
    --principals "testuser,deploy" \
    --validity 8760h \
    --out "$FIXTURES/user-certs/$alg-cert.pub"
done

# --- Issue Host Certificates ---
for alg in "${ALGORITHMS[@]}"; do
  echo "  [host-cert] Issuing $alg host certificate..."
  $QPKI ssh issue \
    --ca-dir "$FIXTURES/host-ca/$alg" \
    --public-key "$FIXTURES/keys/host-$alg.pub" \
    --key-id "host-$alg.crosstest.local" \
    --principals "host-$alg.crosstest.local,192.168.1.10" \
    --validity 8760h \
    --out "$FIXTURES/host-certs/$alg-cert.pub"
done

# --- Issue certificate with critical options (force-command + source-address) ---
echo "  [user-cert] Issuing Ed25519 certificate with critical options..."
ssh-keygen -t ed25519 -f "$FIXTURES/keys/restricted" -N "" -q
$QPKI ssh issue \
  --ca-dir "$FIXTURES/user-ca/ed25519" \
  --public-key "$FIXTURES/keys/restricted.pub" \
  --key-id "restricted@crosstest" \
  --principals "deploy" \
  --validity 8760h \
  --force-command "/usr/bin/deploy.sh" \
  --source-address "10.0.0.0/8" \
  --out "$FIXTURES/user-certs/restricted-cert.pub"

# --- Issue certificate with limited extensions (no-pty) ---
echo "  [user-cert] Issuing Ed25519 certificate with no-pty..."
ssh-keygen -t ed25519 -f "$FIXTURES/keys/no-pty" -N "" -q
$QPKI ssh issue \
  --ca-dir "$FIXTURES/user-ca/ed25519" \
  --public-key "$FIXTURES/keys/no-pty.pub" \
  --key-id "nopty@crosstest" \
  --principals "ciuser" \
  --validity 8760h \
  --no-pty \
  --out "$FIXTURES/user-certs/no-pty-cert.pub"

# --- Revocation & KRL ---
echo "  [krl] Issuing certificate to be revoked..."
ssh-keygen -t ed25519 -f "$FIXTURES/keys/revoked" -N "" -q
$QPKI ssh issue \
  --ca-dir "$FIXTURES/user-ca/ed25519" \
  --public-key "$FIXTURES/keys/revoked.pub" \
  --key-id "revoked@crosstest" \
  --principals "revokeduser" \
  --validity 8760h \
  --out "$FIXTURES/user-certs/revoked-cert.pub"

# Get the serial of the revoked cert (last issued = highest serial)
REVOKED_SERIAL=$($QPKI ssh list --ca-dir "$FIXTURES/user-ca/ed25519" 2>/dev/null | tail -1 | awk '{print $1}')
echo "  [krl] Revoking serial $REVOKED_SERIAL..."
$QPKI ssh revoke --ca-dir "$FIXTURES/user-ca/ed25519" --serial "$REVOKED_SERIAL"

echo "  [krl] Generating KRL..."
$QPKI ssh krl --ca-dir "$FIXTURES/user-ca/ed25519" --out "$FIXTURES/krl/krl.bin" --comment "Cross-test KRL"

# Copy the valid cert for KRL pass test
cp "$FIXTURES/user-certs/ed25519-cert.pub" "$FIXTURES/krl/valid-cert.pub"
cp "$FIXTURES/user-certs/revoked-cert.pub" "$FIXTURES/krl/revoked-cert.pub"

echo ""
echo "=== SSH Fixtures Generated ==="
echo "  Location: $FIXTURES"
echo ""
echo "  User CAs:    $(ls -d "$FIXTURES/user-ca"/*/ | wc -l | tr -d ' ')"
echo "  Host CAs:    $(ls -d "$FIXTURES/host-ca"/*/ | wc -l | tr -d ' ')"
echo "  User Certs:  $(ls "$FIXTURES/user-certs"/*.pub | wc -l | tr -d ' ')"
echo "  Host Certs:  $(ls "$FIXTURES/host-certs"/*.pub | wc -l | tr -d ' ')"
echo "  KRL:         $(ls "$FIXTURES/krl"/*.bin 2>/dev/null | wc -l | tr -d ' ')"
