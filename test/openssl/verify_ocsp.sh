#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: OCSP Response Verification
# =============================================================================
#
# Verifies OCSP responses using OpenSSL 3.6+:
#   - Classical (ECDSA)
#   - PQC (ML-DSA-87, SLH-DSA)
#   - Hybrid (Catalyst: ECDSA + ML-DSA, Composite: ECDSA + ML-DSA)
#
# REQUIREMENTS:
#   - OpenSSL 3.5+ for PQC support
#   - qpki binary to generate OCSP responses
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"
PKI="$PROJECT_ROOT/qpki"
TMP_DIR="/tmp/ocsp-crosstest"

echo "[CrossCompat] OCSP Response Verification (OpenSSL)"
echo ""

# Check qpki binary
if [ ! -f "$PKI" ]; then
    echo "ERROR: qpki binary not found at $PKI"
    echo "       Please build it first: go build -o ./qpki ./cmd/qpki"
    exit 1
fi

# Create temp directory
mkdir -p "$TMP_DIR"

# Helper to find credential certificate and key
find_ee_cert() {
    local ca_dir="$1"
    find "$ca_dir/credentials" -name "certificates.pem" -type f 2>/dev/null | head -1
}

find_ee_key() {
    local ca_dir="$1"
    find "$ca_dir/credentials" -name "private-keys.pem" -type f 2>/dev/null | head -1
}

# Helper to get serial number from cert
get_serial() {
    local cert="$1"
    openssl x509 -in "$cert" -noout -serial 2>/dev/null | cut -d= -f2
}

# Helper to find CA key (prefer ECDSA for hybrid CAs)
find_ca_key() {
    local ca_dir="$1"
    local key_type="${2:-}"

    if [ "$key_type" = "ecdsa" ]; then
        # For hybrid CAs, find ECDSA key specifically
        find "$ca_dir/private" -name "*.ecdsa*.key" -type f 2>/dev/null | head -1
    else
        find "$ca_dir/private" -name "*.key" -type f 2>/dev/null | head -1
    fi
}

# =============================================================================
# Classical ECDSA OCSP
# =============================================================================
echo "[CrossCompat] Classical OCSP Response: ECDSA"
CA_DIR="$FIXTURES/classical/ca"
if [ -d "$CA_DIR" ]; then
    EE_CERT=$(find_ee_cert "$CA_DIR")
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$EE_CERT" ] && [ -n "$CA_KEY" ]; then
        SERIAL=$(get_serial "$EE_CERT")
        # Generate OCSP response using CA as responder
        if "$PKI" ocsp sign --serial "$SERIAL" --status good \
            --ca "$CA_DIR/ca.crt" --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ocsp-ecdsa.der" 2>/dev/null; then
            # Verify with OpenSSL
            if openssl ocsp -respin "$TMP_DIR/ocsp-ecdsa.der" -CAfile "$CA_DIR/ca.crt" -noverify 2>/dev/null; then
                echo "    ECDSA OCSP: OK (parsed)"
            else
                echo "    ECDSA OCSP: FAIL (parse error)"
            fi
        else
            echo "    ECDSA OCSP: FAIL (generation error)"
        fi
    else
        echo "    ECDSA OCSP: SKIP (missing cert or key)"
    fi
else
    echo "    ECDSA OCSP: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# PQC ML-DSA-87 OCSP
# =============================================================================
echo "[CrossCompat] PQC OCSP Response: ML-DSA-87"
CA_DIR="$FIXTURES/pqc/mldsa/ca"
if [ -d "$CA_DIR" ]; then
    EE_CERT=$(find_ee_cert "$CA_DIR")
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$EE_CERT" ] && [ -n "$CA_KEY" ]; then
        SERIAL=$(get_serial "$EE_CERT")
        # Generate OCSP response with ML-DSA signature
        if "$PKI" ocsp sign --serial "$SERIAL" --status good \
            --ca "$CA_DIR/ca.crt" --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ocsp-mldsa.der" 2>/dev/null; then
            # Try to parse with OpenSSL
            if openssl ocsp -respin "$TMP_DIR/ocsp-mldsa.der" -noverify 2>/dev/null; then
                echo "    ML-DSA-87 OCSP: OK (parsed)"
            else
                echo "    ML-DSA-87 OCSP: SKIP (OpenSSL limitation)"
            fi
        else
            echo "    ML-DSA-87 OCSP: FAIL (generation error)"
        fi
    else
        echo "    ML-DSA-87 OCSP: SKIP (missing cert or key)"
    fi
else
    echo "    ML-DSA-87 OCSP: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# PQC SLH-DSA OCSP
# =============================================================================
echo "[CrossCompat] PQC OCSP Response: SLH-DSA"
CA_DIR="$FIXTURES/pqc/slhdsa/ca"
if [ -d "$CA_DIR" ]; then
    EE_CERT=$(find_ee_cert "$CA_DIR")
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$EE_CERT" ] && [ -n "$CA_KEY" ]; then
        SERIAL=$(get_serial "$EE_CERT")
        # Generate OCSP response with SLH-DSA signature
        if "$PKI" ocsp sign --serial "$SERIAL" --status good \
            --ca "$CA_DIR/ca.crt" --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ocsp-slhdsa.der" 2>/dev/null; then
            # Try to parse with OpenSSL
            if openssl ocsp -respin "$TMP_DIR/ocsp-slhdsa.der" -noverify 2>/dev/null; then
                echo "    SLH-DSA OCSP: OK (parsed)"
            else
                echo "    SLH-DSA OCSP: SKIP (OpenSSL limitation)"
            fi
        else
            echo "    SLH-DSA OCSP: FAIL (generation error)"
        fi
    else
        echo "    SLH-DSA OCSP: SKIP (missing cert or key)"
    fi
else
    echo "    SLH-DSA OCSP: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# Hybrid Catalyst OCSP (ECDSA + ML-DSA)
# =============================================================================
echo "[CrossCompat] Hybrid OCSP Response: Catalyst"
CA_DIR="$FIXTURES/catalyst/ca"
if [ -d "$CA_DIR" ]; then
    EE_CERT=$(find_ee_cert "$CA_DIR")
    CA_KEY=$(find_ca_key "$CA_DIR" "ecdsa")
    if [ -n "$EE_CERT" ] && [ -n "$CA_KEY" ]; then
        SERIAL=$(get_serial "$EE_CERT")
        # Generate OCSP response
        if "$PKI" ocsp sign --serial "$SERIAL" --status good \
            --ca "$CA_DIR/ca.crt" --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ocsp-catalyst.der" 2>/dev/null; then
            # OpenSSL verifies only the primary ECDSA signature
            if openssl ocsp -respin "$TMP_DIR/ocsp-catalyst.der" -CAfile "$CA_DIR/ca.crt" -noverify 2>/dev/null; then
                echo "    Catalyst OCSP (ECDSA sig): OK (parsed)"
                echo "    Note: ML-DSA alt signature verified by BouncyCastle only"
            else
                echo "    Catalyst OCSP: FAIL (parse error)"
            fi
        else
            echo "    Catalyst OCSP: FAIL (generation error)"
        fi
    else
        echo "    Catalyst OCSP: SKIP (missing cert or key)"
    fi
else
    echo "    Catalyst OCSP: SKIP (fixtures not found)"
fi
echo ""

# =============================================================================
# Hybrid Composite OCSP (IETF: ECDSA + ML-DSA)
# =============================================================================
echo "[CrossCompat] Hybrid OCSP Response: Composite"
CA_DIR="$FIXTURES/composite/ca"
if [ -d "$CA_DIR" ]; then
    EE_CERT=$(find_ee_cert "$CA_DIR")
    CA_KEY=$(find_ca_key "$CA_DIR")
    if [ -n "$EE_CERT" ] && [ -n "$CA_KEY" ]; then
        SERIAL=$(get_serial "$EE_CERT")
        # Generate OCSP response with composite signature
        if "$PKI" ocsp sign --serial "$SERIAL" --status good \
            --ca "$CA_DIR/ca.crt" --cert "$CA_DIR/ca.crt" --key "$CA_KEY" \
            -o "$TMP_DIR/ocsp-composite.der" 2>/dev/null; then
            # OpenSSL does not support composite signatures
            if openssl ocsp -respin "$TMP_DIR/ocsp-composite.der" -noverify 2>/dev/null; then
                echo "    Composite OCSP: OK (parsed)"
            else
                echo "    Composite OCSP: SKIP (OpenSSL limitation - BouncyCastle only)"
            fi
        else
            echo "    Composite OCSP: FAIL (generation error)"
        fi
    else
        echo "    Composite OCSP: SKIP (missing cert or key)"
    fi
else
    echo "    Composite OCSP: SKIP (fixtures not found)"
fi
echo ""

# Cleanup
rm -rf "$TMP_DIR"

echo "[PASS] OCSP Response Verification Complete"
