package crypto

import "testing"

func TestIsSSHCompatible(t *testing.T) {
	tests := []struct {
		alg  AlgorithmID
		want bool
	}{
		{AlgEd25519, true},
		{AlgECDSAP256, true},
		{AlgECP256, true},
		{AlgECDSAP384, true},
		{AlgECDSAP521, true},
		{AlgRSA2048, true},
		{AlgRSA4096, true},
		// PQC algorithms are NOT SSH-compatible
		{AlgMLDSA44, false},
		{AlgMLDSA65, false},
		{AlgMLDSA87, false},
		{AlgSLHDSASHA2128f, false},
		{AlgMLKEM768, false},
		{AlgHybridP256MLDSA44, false},
		// Unknown
		{AlgorithmID("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			if got := tt.alg.IsSSHCompatible(); got != tt.want {
				t.Errorf("IsSSHCompatible(%s) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestSSHCertAlgorithm(t *testing.T) {
	tests := []struct {
		alg     AlgorithmID
		want    string
		wantErr bool
	}{
		{AlgEd25519, SSHCertAlgoED25519, false},
		{AlgECDSAP256, SSHCertAlgoECDSA256, false},
		{AlgECP256, SSHCertAlgoECDSA256, false},
		{AlgRSA4096, SSHCertAlgoRSASHA256, false},
		{AlgMLDSA65, "", true},
		{AlgHybridP256MLDSA44, "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got, err := tt.alg.SSHCertAlgorithm()
			if (err != nil) != tt.wantErr {
				t.Errorf("SSHCertAlgorithm(%s) error = %v, wantErr %v", tt.alg, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SSHCertAlgorithm(%s) = %v, want %v", tt.alg, got, tt.want)
			}
		})
	}
}

func TestSSHCompatibleAlgorithms(t *testing.T) {
	algs := SSHCompatibleAlgorithms()
	if len(algs) == 0 {
		t.Fatal("SSHCompatibleAlgorithms() returned empty list")
	}

	for _, alg := range algs {
		if !alg.IsSSHCompatible() {
			t.Errorf("SSHCompatibleAlgorithms() returned non-SSH-compatible algorithm: %s", alg)
		}
	}
}
