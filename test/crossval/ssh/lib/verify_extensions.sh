#!/usr/bin/env bash
# verify_extensions.sh — Verify SSH certificate extensions and critical options
#
# Test cases:
#   TC-XSSH-EXT-FC   : force-command critical option
#   TC-XSSH-EXT-SA   : source-address critical option
#   TC-XSSH-EXT-PTY  : permit-pty extension present
#   TC-XSSH-EXT-NOPTY: permit-pty extension absent (no-pty)
#   TC-XSSH-PRINC-OK : principals match

run_extension_tests() {
  local fixtures="$1"

  # --- TC-XSSH-EXT-FC: force-command ---
  local tc="TC-XSSH-EXT-FC"
  local cert="$fixtures/user-certs/restricted-cert.pub"
  if [ -f "$cert" ]; then
    local output
    output=$(ssh-keygen -L -f "$cert" 2>&1)
    if echo "$output" | grep -q "force-command"; then
      set_result "$tc" "PASS" "force-command critical option present"
    else
      set_result "$tc" "FAIL" "force-command not found in cert"
    fi
  else
    set_result "$tc" "SKIP" "restricted cert not found"
  fi

  # --- TC-XSSH-EXT-SA: source-address ---
  tc="TC-XSSH-EXT-SA"
  if [ -f "$cert" ]; then
    local output
    output=$(ssh-keygen -L -f "$cert" 2>&1)
    if echo "$output" | grep -q "source-address"; then
      set_result "$tc" "PASS" "source-address critical option present"
    else
      set_result "$tc" "FAIL" "source-address not found in cert"
    fi
  else
    set_result "$tc" "SKIP" "restricted cert not found"
  fi

  # --- TC-XSSH-EXT-PTY: permit-pty present (default user cert) ---
  tc="TC-XSSH-EXT-PTY"
  cert="$fixtures/user-certs/ed25519-cert.pub"
  if [ -f "$cert" ]; then
    local output
    output=$(ssh-keygen -L -f "$cert" 2>&1)
    if echo "$output" | grep -q "permit-pty"; then
      set_result "$tc" "PASS" "permit-pty extension present"
    else
      set_result "$tc" "FAIL" "permit-pty not found"
    fi
  else
    set_result "$tc" "SKIP" "ed25519 user cert not found"
  fi

  # --- TC-XSSH-EXT-NOPTY: permit-pty absent (no-pty cert) ---
  tc="TC-XSSH-EXT-NOPTY"
  cert="$fixtures/user-certs/no-pty-cert.pub"
  if [ -f "$cert" ]; then
    local output
    output=$(ssh-keygen -L -f "$cert" 2>&1)
    if echo "$output" | grep -q "permit-pty"; then
      set_result "$tc" "FAIL" "permit-pty should NOT be present in no-pty cert"
    else
      set_result "$tc" "PASS" "permit-pty correctly absent"
    fi
  else
    set_result "$tc" "SKIP" "no-pty cert not found"
  fi

  # --- TC-XSSH-PRINC-OK: principals match ---
  tc="TC-XSSH-PRINC-OK"
  cert="$fixtures/user-certs/ed25519-cert.pub"
  if [ -f "$cert" ]; then
    local output
    output=$(ssh-keygen -L -f "$cert" 2>&1)
    if echo "$output" | grep -q "testuser"; then
      set_result "$tc" "PASS" "principal 'testuser' found in cert"
    else
      set_result "$tc" "FAIL" "principal 'testuser' not found"
    fi
  else
    set_result "$tc" "SKIP" "ed25519 user cert not found"
  fi

  # --- TC-XSSH-VALID: validity window ---
  tc="TC-XSSH-VALID"
  if [ -f "$cert" ]; then
    local output
    output=$(ssh-keygen -L -f "$cert" 2>&1)
    if echo "$output" | grep -q "Valid:"; then
      set_result "$tc" "PASS" "validity window present"
    else
      set_result "$tc" "FAIL" "validity window not found"
    fi
  else
    set_result "$tc" "SKIP" "ed25519 user cert not found"
  fi
}
