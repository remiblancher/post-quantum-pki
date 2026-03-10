#!/bin/bash
# =============================================================================
# OpenSSH Cross-Test Orchestrator
# =============================================================================
#
# Runs all SSH certificate cross-validation tests using OpenSSH tools
# (ssh-keygen -L, ssh-keygen -Q) and generates a summary matrix.
#
# Usage: ./test/crossval/ssh/run_all.sh
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$SCRIPT_DIR/../fixtures/ssh"
LIB_DIR="$SCRIPT_DIR/lib"
RESULTS_DIR="$SCRIPT_DIR/results"

mkdir -p "$RESULTS_DIR"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Results storage
RESULTS_FILE=$(mktemp)
DETAILS_FILE=$(mktemp)
trap "rm -f $RESULTS_FILE $DETAILS_FILE" EXIT

# =============================================================================
# Helper Functions
# =============================================================================

set_result() {
    local tc_id="$1"
    local status="$2"  # PASS, FAIL, SKIP
    local detail="${3:-}"
    echo "$tc_id=$status" >> "$RESULTS_FILE"
    if [ -n "$detail" ]; then
      echo "$tc_id: $detail" >> "$DETAILS_FILE"
    fi

    case "$status" in
      PASS) echo -e "  ${GREEN}✓${NC} $tc_id: $detail" ;;
      FAIL) echo -e "  ${RED}✗${NC} $tc_id: $detail" ;;
      SKIP) echo -e "  ${YELLOW}⊘${NC} $tc_id: $detail" ;;
    esac
}

get_result() {
    local tc_id="$1"
    local result
    result=$(grep "^${tc_id}=" "$RESULTS_FILE" 2>/dev/null | tail -1 | cut -d= -f2)
    echo "${result:-N/A}"
}

count_results() {
    local status="$1"
    grep "=$status$" "$RESULTS_FILE" 2>/dev/null | wc -l | tr -d ' '
}

# =============================================================================
# Check Prerequisites
# =============================================================================

echo "============================================================"
echo "[CrossCompat] OpenSSH Certificate Interoperability Tests"
echo "============================================================"
echo ""

SSH_VERSION=$(ssh -V 2>&1 | head -1)
echo "OpenSSH: $SSH_VERSION"
echo ""

if [ ! -d "$FIXTURES" ]; then
    echo -e "${RED}ERROR: Fixtures not found at $FIXTURES${NC}"
    echo "       Run ./test/crossval/generate_qpki_ssh_fixtures.sh first"
    exit 1
fi

# =============================================================================
# Source Test Libraries
# =============================================================================

for lib in verify_user_cert verify_host_cert verify_extensions verify_krl; do
  source "$LIB_DIR/${lib}.sh"
done

# =============================================================================
# Run Tests
# =============================================================================

echo "--- User Certificate Tests ---"
run_user_cert_tests "$FIXTURES"
echo ""

echo "--- Host Certificate Tests ---"
run_host_cert_tests "$FIXTURES"
echo ""

echo "--- Extension & Principal Tests ---"
run_extension_tests "$FIXTURES"
echo ""

echo "--- KRL Revocation Tests ---"
run_krl_tests "$FIXTURES"
echo ""

# =============================================================================
# Summary
# =============================================================================

TOTAL=$(wc -l < "$RESULTS_FILE" | tr -d ' ')
PASSED=$(count_results "PASS")
FAILED=$(count_results "FAIL")
SKIPPED=$(count_results "SKIP")

echo "============================================================"
echo "  Results: $PASSED passed, $FAILED failed, $SKIPPED skipped (total: $TOTAL)"
echo "============================================================"

# =============================================================================
# Generate JSON Results
# =============================================================================

START_TIME=$(date +%s%3N 2>/dev/null || date +%s)
END_TIME=$(date +%s%3N 2>/dev/null || date +%s)

# results-ssh.json
{
  echo "{"
  echo "  \"tool\": \"OpenSSH\","
  echo "  \"version\": \"$(ssh -V 2>&1 | head -1)\","
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"tests\": ["

  first=true
  while IFS='=' read -r tc_id status; do
    detail=$(grep "^$tc_id:" "$DETAILS_FILE" 2>/dev/null | cut -d: -f2- | sed 's/^ //')
    if [ "$first" = true ]; then
      first=false
    else
      echo "    ,"
    fi
    echo "    {"
    echo "      \"id\": \"$tc_id\","
    echo "      \"status\": \"$status\","
    echo "      \"detail\": \"${detail:-}\""
    echo -n "    }"
  done < "$RESULTS_FILE"

  echo ""
  echo "  ],"
  echo "  \"summary\": {"
  echo "    \"total\": $TOTAL,"
  echo "    \"passed\": $PASSED,"
  echo "    \"failed\": $FAILED,"
  echo "    \"skipped\": $SKIPPED"
  echo "  }"
  echo "}"
} > "$RESULTS_DIR/results-ssh.json"

# ctrf-crosstest-ssh.json (CTRF format)
{
  echo "{"
  echo "  \"results\": {"
  echo "    \"tool\": { \"name\": \"crosstest-ssh\" },"
  echo "    \"summary\": {"
  echo "      \"tests\": $TOTAL,"
  echo "      \"passed\": $PASSED,"
  echo "      \"failed\": $FAILED,"
  echo "      \"skipped\": $SKIPPED,"
  echo "      \"pending\": 0,"
  echo "      \"other\": 0,"
  echo "      \"start\": $START_TIME,"
  echo "      \"stop\": $END_TIME"
  echo "    },"
  echo "    \"tests\": ["

  first=true
  while IFS='=' read -r tc_id status; do
    ctrf_status="passed"
    case "$status" in
      PASS) ctrf_status="passed" ;;
      FAIL) ctrf_status="failed" ;;
      SKIP) ctrf_status="skipped" ;;
    esac
    if [ "$first" = true ]; then
      first=false
    else
      echo "      ,"
    fi
    echo "      {"
    echo "        \"name\": \"$tc_id\","
    echo "        \"status\": \"$ctrf_status\","
    echo "        \"duration\": 0"
    echo -n "      }"
  done < "$RESULTS_FILE"

  echo ""
  echo "    ]"
  echo "  }"
  echo "}"
} > "$RESULTS_DIR/ctrf-crosstest-ssh.json"

echo ""
echo "Results written to:"
echo "  $RESULTS_DIR/results-ssh.json"
echo "  $RESULTS_DIR/ctrf-crosstest-ssh.json"

# Exit with failure if any tests failed
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
