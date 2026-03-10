// Package crypto provides cryptographic primitives for the PKI.
// This file provides SSH certificate algorithm mapping and validation.
package crypto

import "fmt"

// SSH certificate algorithm type strings (OpenSSH PROTOCOL.certkeys).
const (
	SSHCertAlgoRSA        = "ssh-rsa-cert-v01@openssh.com"
	SSHCertAlgoRSASHA256  = "rsa-sha2-256-cert-v01@openssh.com"
	SSHCertAlgoRSASHA512  = "rsa-sha2-512-cert-v01@openssh.com"
	SSHCertAlgoECDSA256   = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	SSHCertAlgoECDSA384   = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	SSHCertAlgoECDSA521   = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
	SSHCertAlgoED25519    = "ssh-ed25519-cert-v01@openssh.com"
)

// sshAlgorithmMap maps qpki AlgorithmID to SSH certificate algorithm strings.
var sshAlgorithmMap = map[AlgorithmID]string{
	AlgEd25519:   SSHCertAlgoED25519,
	AlgECDSAP256: SSHCertAlgoECDSA256,
	AlgECP256:    SSHCertAlgoECDSA256,
	AlgECDSAP384: SSHCertAlgoECDSA384,
	AlgECP384:    SSHCertAlgoECDSA384,
	AlgECDSAP521: SSHCertAlgoECDSA521,
	AlgECP521:    SSHCertAlgoECDSA521,
	AlgRSA2048:   SSHCertAlgoRSASHA256,
	AlgRSA4096:   SSHCertAlgoRSASHA256,
}

// IsSSHCompatible returns true if the algorithm can be used for SSH certificates.
// Only classical signature algorithms are supported — SSH has no PQC signature standard.
func (a AlgorithmID) IsSSHCompatible() bool {
	_, ok := sshAlgorithmMap[a]
	return ok
}

// SSHCertAlgorithm returns the SSH certificate algorithm string for this AlgorithmID.
// Returns an error if the algorithm is not SSH-compatible.
func (a AlgorithmID) SSHCertAlgorithm() (string, error) {
	if s, ok := sshAlgorithmMap[a]; ok {
		return s, nil
	}
	return "", fmt.Errorf("algorithm %s is not supported for SSH certificates (SSH has no PQC signature standard)", a)
}

// SSHCompatibleAlgorithms returns all algorithms that support SSH certificates.
func SSHCompatibleAlgorithms() []AlgorithmID {
	seen := make(map[AlgorithmID]bool)
	var result []AlgorithmID
	for alg := range sshAlgorithmMap {
		if !seen[alg] {
			seen[alg] = true
			result = append(result, alg)
		}
	}
	return result
}
