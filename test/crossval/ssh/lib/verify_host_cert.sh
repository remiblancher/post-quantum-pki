#!/usr/bin/env bash
# verify_host_cert.sh — Verify SSH host certificate structure with ssh-keygen -L
#
# Test cases:
#   TC-XSSH-HCERT-ED25519  : Ed25519 host certificate
#   TC-XSSH-HCERT-ECDSA    : ECDSA-P256 host certificate
#   TC-XSSH-HCERT-RSA      : RSA-4096 host certificate

_verify_host_cert() {
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

  if ! echo "$output" | grep -qi "host certificate"; then
    set_result "$tc" "FAIL" "Not a host certificate"
    return
  fi

  if ! echo "$output" | grep -q "Signing CA:"; then
    set_result "$tc" "FAIL" "No signing CA found"
    return
  fi

  set_result "$tc" "PASS" "Host cert validated by ssh-keygen -L"
}

run_host_cert_tests() {
  local fixtures="$1"

  _verify_host_cert "TC-XSSH-HCERT-ED25519" \
    "$fixtures/host-certs/ed25519-cert.pub" \
    "ssh-ed25519-cert-v01@openssh.com"

  _verify_host_cert "TC-XSSH-HCERT-ECDSA" \
    "$fixtures/host-certs/ecdsa-p256-cert.pub" \
    "ecdsa-sha2-nistp256-cert-v01@openssh.com"

  _verify_host_cert "TC-XSSH-HCERT-RSA" \
    "$fixtures/host-certs/rsa-4096-cert.pub" \
    "ssh-rsa-cert-v01@openssh.com"
}
