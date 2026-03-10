#!/usr/bin/env bash
# verify_user_cert.sh — Verify SSH user certificate structure with ssh-keygen -L
#
# Test cases:
#   TC-XSSH-UCERT-ED25519  : Ed25519 user certificate
#   TC-XSSH-UCERT-ECDSA    : ECDSA-P256 user certificate
#   TC-XSSH-UCERT-RSA      : RSA-4096 user certificate

_verify_user_cert() {
  local tc="$1"
  local cert="$2"
  local expected_type="$3"

  if [ ! -f "$cert" ]; then
    set_result "$tc" "SKIP" "Certificate file not found"
    return
  fi

  local output
  output=$(ssh-keygen -L -f "$cert" 2>&1)
  if [ $? -ne 0 ]; then
    set_result "$tc" "FAIL" "ssh-keygen -L failed"
    return
  fi

  if ! echo "$output" | grep -q "$expected_type"; then
    set_result "$tc" "FAIL" "Expected type $expected_type not found"
    return
  fi

  if ! echo "$output" | grep -qi "user certificate"; then
    set_result "$tc" "FAIL" "Not a user certificate"
    return
  fi

  if ! echo "$output" | grep -q "Signing CA:"; then
    set_result "$tc" "FAIL" "No signing CA found"
    return
  fi

  set_result "$tc" "PASS" "User cert validated by ssh-keygen -L"
}

run_user_cert_tests() {
  local fixtures="$1"

  _verify_user_cert "TC-XSSH-UCERT-ED25519" \
    "$fixtures/user-certs/ed25519-cert.pub" \
    "ssh-ed25519-cert-v01@openssh.com"

  _verify_user_cert "TC-XSSH-UCERT-ECDSA" \
    "$fixtures/user-certs/ecdsa-p256-cert.pub" \
    "ecdsa-sha2-nistp256-cert-v01@openssh.com"

  _verify_user_cert "TC-XSSH-UCERT-RSA" \
    "$fixtures/user-certs/rsa-4096-cert.pub" \
    "ssh-rsa-cert-v01@openssh.com"
}
