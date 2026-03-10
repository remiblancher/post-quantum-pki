#!/usr/bin/env bash
# verify_krl.sh — Verify KRL (Key Revocation List) with ssh-keygen -Q
#
# Test cases:
#   TC-XSSH-KRL-CHK  : Revoked cert detected by KRL
#   TC-XSSH-KRL-PASS : Valid cert passes KRL check

run_krl_tests() {
  local fixtures="$1"
  local krl="$fixtures/krl/krl.bin"

  if [ ! -f "$krl" ]; then
    set_result "TC-XSSH-KRL-CHK" "SKIP" "KRL file not found"
    set_result "TC-XSSH-KRL-PASS" "SKIP" "KRL file not found"
    return
  fi

  # --- TC-XSSH-KRL-CHK: Revoked cert should be flagged ---
  local tc="TC-XSSH-KRL-CHK"
  local revoked_cert="$fixtures/krl/revoked-cert.pub"
  if [ -f "$revoked_cert" ]; then
    local output
    # ssh-keygen -Q returns exit code 1 for revoked certs — use || true to avoid set -e
    output=$(ssh-keygen -Q -f "$krl" "$revoked_cert" 2>&1) || true
    if echo "$output" | grep -qi "REVOKED"; then
      set_result "$tc" "PASS" "Revoked cert correctly identified by ssh-keygen -Q"
    else
      set_result "$tc" "FAIL" "ssh-keygen -Q did not flag revoked cert: $output"
    fi
  else
    set_result "$tc" "SKIP" "Revoked cert not found"
  fi

  # --- TC-XSSH-KRL-PASS: Valid cert should pass ---
  tc="TC-XSSH-KRL-PASS"
  local valid_cert="$fixtures/krl/valid-cert.pub"
  if [ -f "$valid_cert" ]; then
    local output
    output=$(ssh-keygen -Q -f "$krl" "$valid_cert" 2>&1) || true
    if echo "$output" | grep -qi "REVOKED"; then
      set_result "$tc" "FAIL" "ssh-keygen -Q incorrectly flagged valid cert: $output"
    else
      set_result "$tc" "PASS" "Valid cert correctly passed KRL check"
    fi
  else
    set_result "$tc" "SKIP" "Valid cert not found"
  fi
}
