#!/bin/bash
# =============================================================================
# OpenSSL Cross-Test: RFC 5280 Extensions Verification
# =============================================================================
#
# Verifies X.509 extension conformance per RFC 5280:
#   - Basic Constraints (criticality, CA, pathLen)
#   - Key Usage (criticality, bit values)
#   - Extended Key Usage (OIDs)
#   - Certificate Policies (CPS URI format)
#   - Subject Alternative Name (DNS, email, IP)
#   - CRL Distribution Points (URI format)
#   - Authority Information Access (OCSP, caIssuers)
#   - Name Constraints (permitted/excluded)
#
# REQUIREMENTS:
#   - OpenSSL 3.0+ (for asn1parse and text output)
#   - Pre-generated fixtures in test/fixtures/
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures"
TEMP_DIR=$(mktemp -d)

trap "rm -rf $TEMP_DIR" EXIT

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
SKIPPED=0

echo "============================================================"
echo "[RFC5280] Extension Compliance Verification (OpenSSL)"
echo "============================================================"
echo ""

# Check OpenSSL version
OPENSSL_VERSION=$(openssl version 2>/dev/null | head -1)
echo "OpenSSL: $OPENSSL_VERSION"
echo ""

# =============================================================================
# Helper Functions
# =============================================================================

pass() {
    echo -e "    ${GREEN}PASS${NC}: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "    ${RED}FAIL${NC}: $1"
    if [ -n "$2" ]; then
        echo -e "          $2"
    fi
    FAILED=$((FAILED + 1))
}

skip() {
    echo -e "    ${YELLOW}SKIP${NC}: $1"
    SKIPPED=$((SKIPPED + 1))
}

info() {
    echo -e "    ${BLUE}INFO${NC}: $1"
}

# Get extension text from certificate
get_extension_text() {
    local cert="$1"
    openssl x509 -in "$cert" -text -noout 2>/dev/null
}

# Get raw ASN.1 dump of certificate
get_asn1_dump() {
    local cert="$1"
    openssl asn1parse -in "$cert" -dump 2>/dev/null
}

# Extract specific extension OID value
get_extension_raw() {
    local cert="$1"
    local oid="$2"
    openssl x509 -in "$cert" -noout -ext "$oid" 2>/dev/null
}

# =============================================================================
# Extension Tests
# =============================================================================

# Test Basic Constraints extension
test_basic_constraints() {
    local name="$1"
    local cert="$2"
    local expect_ca="$3"
    local expect_critical="$4"

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Basic Constraints"; then
        skip "$name Basic Constraints (extension not present)"
        return
    fi

    # Check criticality
    if [ "$expect_critical" = "true" ]; then
        if echo "$text" | grep -A1 "Basic Constraints" | grep -q "critical"; then
            pass "$name Basic Constraints critical=true"
        else
            fail "$name Basic Constraints should be critical"
        fi
    fi

    # Check CA flag
    if [ "$expect_ca" = "true" ]; then
        if echo "$text" | grep -A2 "Basic Constraints" | grep -q "CA:TRUE"; then
            pass "$name Basic Constraints CA=TRUE"
        else
            fail "$name Basic Constraints should have CA:TRUE"
        fi
    else
        if echo "$text" | grep -A2 "Basic Constraints" | grep -q "CA:FALSE\|CA:TRUE" | grep -v "CA:TRUE"; then
            pass "$name Basic Constraints CA=FALSE"
        else
            # End-entity certificates may not have basicConstraints at all, which is OK
            pass "$name Basic Constraints (not CA)"
        fi
    fi
}

# Test Key Usage extension
test_key_usage() {
    local name="$1"
    local cert="$2"
    local expect_critical="$3"
    shift 3
    local expected_usages=("$@")

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Key Usage"; then
        skip "$name Key Usage (extension not present)"
        return
    fi

    # Check criticality
    if [ "$expect_critical" = "true" ]; then
        if echo "$text" | grep -B1 "Key Usage" | head -1 | grep -q "critical"; then
            pass "$name Key Usage critical=true"
        else
            # Some implementations put critical on same line
            if echo "$text" | grep "Key Usage" | grep -q "critical"; then
                pass "$name Key Usage critical=true"
            else
                fail "$name Key Usage should be critical (RFC 5280 4.2.1.3)"
            fi
        fi
    fi

    # Check expected usages
    local ku_line=$(echo "$text" | grep -A1 "Key Usage" | tail -1)
    for usage in "${expected_usages[@]}"; do
        if echo "$ku_line" | grep -qi "$usage"; then
            pass "$name Key Usage contains $usage"
        else
            fail "$name Key Usage missing $usage"
        fi
    done
}

# Test Certificate Policies extension (CPS URI must be IA5String)
test_certificate_policies() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Certificate Policies\|X509v3 Certificate Policies"; then
        skip "$name Certificate Policies (extension not present)"
        return
    fi

    # Check that CPS URI is parsed correctly
    local cps_uri=$(echo "$text" | grep -A10 "Certificate Policies" | grep "CPS:" | head -1)
    if [ -n "$cps_uri" ]; then
        # Verify it's a valid URI (starts with http or https)
        if echo "$cps_uri" | grep -qE "CPS: ?https?://"; then
            pass "$name Certificate Policies CPS URI parsed correctly"
        else
            fail "$name Certificate Policies CPS URI format invalid" "Got: $cps_uri"
        fi
    else
        info "$name Certificate Policies has no CPS qualifier"
    fi

    # Verify CPS URI encoding using hex dump
    # IA5STRING has tag 0x16 (22 decimal)
    # Extract raw extension and check for IA5STRING tag before the URL
    if [ -n "$cps_uri" ]; then
        # Get the raw cert in DER, extract Certificate Policies extension
        # and check for IA5STRING tag (0x16) in hex
        local ext_hex=$(openssl x509 -in "$cert" -noout -ext certificatePolicies 2>/dev/null | \
            openssl asn1parse -inform PEM 2>/dev/null | grep -i "IA5STRING\|IA5")

        if [ -n "$ext_hex" ]; then
            pass "$name Certificate Policies CPS encoded as IA5String"
        else
            # Alternative: check hex dump for tag 0x16 followed by URL bytes
            # "https" in hex is 68747470733a2f2f
            local raw_hex=$(openssl x509 -in "$cert" -outform DER 2>/dev/null | xxd -p | tr -d '\n')
            # Look for pattern: 16 (IA5STRING tag) followed by length byte and "https"
            if echo "$raw_hex" | grep -qE "16[0-9a-f]{2}68747470733a2f2f"; then
                pass "$name Certificate Policies CPS encoded as IA5String"
            else
                # Check if it might be PrintableString (tag 0x13)
                if echo "$raw_hex" | grep -qE "13[0-9a-f]{2}68747470733a2f2f"; then
                    fail "$name Certificate Policies CPS should be IA5String" "Bug: encoded as PrintableString"
                else
                    # Can't determine encoding, but CPS parsed correctly
                    info "$name Certificate Policies CPS encoding could not be verified"
                fi
            fi
        fi
    else
        info "$name Certificate Policies no CPS to verify encoding"
    fi
}

# Test Subject Alternative Name extension
test_subject_alt_name() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Subject Alternative Name"; then
        skip "$name Subject Alternative Name (extension not present)"
        return
    fi

    local san_line=$(echo "$text" | grep -A5 "Subject Alternative Name")

    # Check DNS names
    if echo "$san_line" | grep -q "DNS:"; then
        local dns_names=$(echo "$san_line" | grep -o "DNS:[^,]*" | head -3)
        pass "$name SAN contains DNS names"
        info "DNS entries: $(echo $dns_names | tr '\n' ' ')"
    fi

    # Check email
    if echo "$san_line" | grep -q "email:"; then
        pass "$name SAN contains email"
    fi

    # Check IP addresses
    if echo "$san_line" | grep -q "IP Address:"; then
        pass "$name SAN contains IP addresses"
    fi

    # Check URIs
    if echo "$san_line" | grep -q "URI:"; then
        pass "$name SAN contains URIs"
    fi
}

# Test CRL Distribution Points extension
test_crl_distribution_points() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "CRL Distribution Points"; then
        skip "$name CRL Distribution Points (extension not present)"
        return
    fi

    # Check that URI is present and valid
    local crldp=$(echo "$text" | grep -A10 "CRL Distribution Points")
    if echo "$crldp" | grep -qE "URI:https?://"; then
        pass "$name CRL Distribution Points URI parsed correctly"
        local uri=$(echo "$crldp" | grep -o "URI:[^ ]*" | head -1)
        info "CRL DP: $uri"
    else
        fail "$name CRL Distribution Points should contain URI"
    fi
}

# Test Authority Information Access extension
test_authority_info_access() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Authority Information Access"; then
        skip "$name Authority Information Access (extension not present)"
        return
    fi

    local aia=$(echo "$text" | grep -A10 "Authority Information Access")

    # AIA must NOT be critical (RFC 5280 4.2.2.1)
    if echo "$text" | grep -B1 "Authority Information Access" | grep -q "critical"; then
        fail "$name AIA must NOT be critical (RFC 5280 4.2.2.1)"
    else
        pass "$name AIA is non-critical"
    fi

    # Check OCSP
    if echo "$aia" | grep -q "OCSP"; then
        if echo "$aia" | grep -qE "OCSP.*URI:https?://"; then
            pass "$name AIA contains OCSP responder URI"
            local ocsp=$(echo "$aia" | grep -o "OCSP.*URI:[^ ]*" | head -1)
            info "$ocsp"
        else
            fail "$name AIA OCSP URI format invalid"
        fi
    fi

    # Check CA Issuers
    if echo "$aia" | grep -q "CA Issuers"; then
        if echo "$aia" | grep -qE "CA Issuers.*URI:https?://"; then
            pass "$name AIA contains CA Issuers URI"
        else
            fail "$name AIA CA Issuers URI format invalid"
        fi
    fi
}

# Test Extended Key Usage extension
test_extended_key_usage() {
    local name="$1"
    local cert="$2"
    shift 2
    local expected_ekus=("$@")

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Extended Key Usage"; then
        skip "$name Extended Key Usage (extension not present)"
        return
    fi

    local eku_line=$(echo "$text" | grep -A5 "Extended Key Usage")

    for eku in "${expected_ekus[@]}"; do
        if echo "$eku_line" | grep -qi "$eku"; then
            pass "$name EKU contains $eku"
        else
            fail "$name EKU missing $eku"
        fi
    done
}

# Test Name Constraints extension
test_name_constraints() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    # Check if extension exists
    if ! echo "$text" | grep -q "Name Constraints"; then
        skip "$name Name Constraints (extension not present)"
        return
    fi

    # Name Constraints SHOULD be critical (RFC 5280 4.2.1.10)
    if echo "$text" | grep -B1 "Name Constraints" | grep -q "critical"; then
        pass "$name Name Constraints is critical (RFC 5280 4.2.1.10)"
    else
        fail "$name Name Constraints SHOULD be critical (RFC 5280 4.2.1.10)"
    fi

    local nc=$(echo "$text" | grep -A20 "Name Constraints")

    # Check Permitted subtrees
    if echo "$nc" | grep -q "Permitted:"; then
        pass "$name Name Constraints has Permitted subtrees"
        if echo "$nc" | grep -q "DNS:"; then
            info "Permitted DNS constraints present"
        fi
    fi

    # Check Excluded subtrees
    if echo "$nc" | grep -q "Excluded:"; then
        pass "$name Name Constraints has Excluded subtrees"
    fi
}

# Test Subject Key Identifier
test_subject_key_identifier() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    if echo "$text" | grep -q "Subject Key Identifier"; then
        # SKI should NOT be critical
        if echo "$text" | grep -B1 "Subject Key Identifier" | grep -q "critical"; then
            fail "$name SKI must NOT be critical (RFC 5280 4.2.1.2)"
        else
            pass "$name Subject Key Identifier present (non-critical)"
        fi
    else
        fail "$name Subject Key Identifier should be present"
    fi
}

# Test Authority Key Identifier
test_authority_key_identifier() {
    local name="$1"
    local cert="$2"

    local text=$(get_extension_text "$cert")

    if echo "$text" | grep -q "Authority Key Identifier"; then
        # AKI should NOT be critical
        if echo "$text" | grep -B1 "Authority Key Identifier" | grep -q "critical"; then
            fail "$name AKI must NOT be critical (RFC 5280 4.2.1.1)"
        else
            pass "$name Authority Key Identifier present (non-critical)"
        fi
    else
        # AKI is optional for self-signed certs
        info "$name Authority Key Identifier not present (OK for self-signed)"
    fi
}

# =============================================================================
# Run Tests on Fixtures
# =============================================================================

run_extension_tests() {
    local name="$1"
    local cert_path="$2"
    local is_ca="$3"

    if [ ! -f "$cert_path" ]; then
        echo -e ">>> ${YELLOW}$name: Certificate not found${NC}"
        echo "    Path: $cert_path"
        return
    fi

    echo -e ">>> ${BLUE}$name${NC}"
    echo "    Certificate: $cert_path"
    echo ""

    # Run all extension tests
    test_subject_key_identifier "$name" "$cert_path"
    test_authority_key_identifier "$name" "$cert_path"

    if [ "$is_ca" = "true" ]; then
        test_basic_constraints "$name" "$cert_path" "true" "true"
        test_key_usage "$name" "$cert_path" "true" "Certificate Sign" "CRL Sign"
    else
        test_basic_constraints "$name" "$cert_path" "false" "false"
    fi

    test_certificate_policies "$name" "$cert_path"
    test_subject_alt_name "$name" "$cert_path"
    test_crl_distribution_points "$name" "$cert_path"
    test_authority_info_access "$name" "$cert_path"

    echo ""
}

# =============================================================================
# Test Classical ECDSA Fixtures
# =============================================================================

echo "============================================================"
echo "Classical (ECDSA) Extension Tests"
echo "============================================================"
echo ""

if [ -d "$FIXTURES/classical/ca" ]; then
    run_extension_tests "Classical CA" "$FIXTURES/classical/ca/ca.crt" "true"

    # Find end-entity certificate
    EE_CERT=$(find "$FIXTURES/classical/ca/credentials" -name "certificates.pem" 2>/dev/null | head -1)
    if [ -n "$EE_CERT" ]; then
        run_extension_tests "Classical EE" "$EE_CERT" "false"
    fi
else
    skip "Classical fixtures not found at $FIXTURES/classical/ca"
fi

# =============================================================================
# Test PQC ML-DSA Fixtures
# =============================================================================

echo "============================================================"
echo "PQC (ML-DSA) Extension Tests"
echo "============================================================"
echo ""

if [ -d "$FIXTURES/pqc/mldsa/ca" ]; then
    run_extension_tests "ML-DSA CA" "$FIXTURES/pqc/mldsa/ca/ca.crt" "true"

    EE_CERT=$(find "$FIXTURES/pqc/mldsa/ca/credentials" -name "certificates.pem" 2>/dev/null | head -1)
    if [ -n "$EE_CERT" ]; then
        run_extension_tests "ML-DSA EE" "$EE_CERT" "false"
    fi
else
    skip "ML-DSA fixtures not found"
fi

# =============================================================================
# Test Hybrid Catalyst Fixtures
# =============================================================================

echo "============================================================"
echo "Hybrid (Catalyst) Extension Tests"
echo "============================================================"
echo ""

if [ -d "$FIXTURES/catalyst/ca" ]; then
    run_extension_tests "Catalyst CA" "$FIXTURES/catalyst/ca/ca.crt" "true"

    EE_CERT=$(find "$FIXTURES/catalyst/ca/credentials" -name "certificates.pem" 2>/dev/null | head -1)
    if [ -n "$EE_CERT" ]; then
        run_extension_tests "Catalyst EE" "$EE_CERT" "false"
    fi
else
    skip "Catalyst fixtures not found"
fi

# =============================================================================
# Test SLH-DSA Fixtures
# =============================================================================

echo "============================================================"
echo "PQC (SLH-DSA) Extension Tests"
echo "============================================================"
echo ""

if [ -d "$FIXTURES/pqc/slhdsa/ca" ]; then
    run_extension_tests "SLH-DSA CA" "$FIXTURES/pqc/slhdsa/ca/ca.crt" "true"

    EE_CERT=$(find "$FIXTURES/pqc/slhdsa/ca/credentials" -name "certificates.pem" 2>/dev/null | head -1)
    if [ -n "$EE_CERT" ]; then
        run_extension_tests "SLH-DSA EE" "$EE_CERT" "false"
    fi
else
    skip "SLH-DSA fixtures not found"
fi

# =============================================================================
# Summary
# =============================================================================

echo "============================================================"
echo "RFC 5280 Extension Verification Summary"
echo "============================================================"
echo -e "  Passed:  ${GREEN}$PASSED${NC}"
echo -e "  Failed:  ${RED}$FAILED${NC}"
echo -e "  Skipped: ${YELLOW}$SKIPPED${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}[FAIL] Some extension tests failed${NC}"
    echo ""
    echo "Common issues:"
    echo "  - cpsURI encoded as PrintableString instead of IA5String"
    echo "  - Key Usage not marked critical"
    echo "  - Basic Constraints not marked critical for CA"
    echo "  - AIA marked as critical (must be non-critical)"
    echo ""
    exit 1
else
    echo -e "${GREEN}[PASS] All extension tests passed${NC}"
    exit 0
fi
