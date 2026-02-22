package pki

import (
	"testing"
	"time"
)

// =============================================================================
// LoadProfile Tests
// =============================================================================

func TestU_LoadProfile(t *testing.T) {
	t.Run("[Unit] LoadProfile: valid built-in profile", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}
		if prof == nil {
			t.Error("LoadProfile() returned nil profile")
		}
		if prof.Name != "ec/tls-server" {
			t.Errorf("LoadProfile() name = %s, want ec/tls-server", prof.Name)
		}
	})

	t.Run("[Unit] LoadProfile: profile not found", func(t *testing.T) {
		_, err := LoadProfile("nonexistent-profile")
		if err == nil {
			t.Error("LoadProfile() should fail for non-existent profile")
		}
	})
}

// =============================================================================
// ListProfiles Tests
// =============================================================================

func TestU_ListProfiles(t *testing.T) {
	t.Run("[Unit] ListProfiles: returns profiles", func(t *testing.T) {
		profiles, err := ListProfiles()
		if err != nil {
			t.Fatalf("ListProfiles() error = %v", err)
		}
		if len(profiles) == 0 {
			t.Error("ListProfiles() returned empty list")
		}
	})

	t.Run("[Unit] ListProfiles: contains common profiles", func(t *testing.T) {
		profiles, err := ListProfiles()
		if err != nil {
			t.Fatalf("ListProfiles() error = %v", err)
		}

		found := make(map[string]bool)
		for _, p := range profiles {
			found[p] = true
		}

		expectedProfiles := []string{"ec/tls-server", "ec/tls-client", "ec/code-signing"}
		for _, expected := range expectedProfiles {
			if !found[expected] {
				t.Errorf("ListProfiles() missing expected profile: %s", expected)
			}
		}
	})
}

// =============================================================================
// GetProfileValidity Tests
// =============================================================================

func TestU_GetProfileValidity(t *testing.T) {
	t.Run("[Unit] GetProfileValidity: returns non-zero duration", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		validity := GetProfileValidity(prof)
		if validity <= 0 {
			t.Error("GetProfileValidity() returned non-positive duration")
		}
	})

	t.Run("[Unit] GetProfileValidity: typical validity is reasonable", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		validity := GetProfileValidity(prof)
		minValidity := 24 * time.Hour            // At least 1 day
		maxValidity := 10 * 365 * 24 * time.Hour // At most 10 years

		if validity < minValidity {
			t.Errorf("GetProfileValidity() = %v, want at least %v", validity, minValidity)
		}
		if validity > maxValidity {
			t.Errorf("GetProfileValidity() = %v, want at most %v", validity, maxValidity)
		}
	})
}

// =============================================================================
// GetProfileAlgorithm Tests
// =============================================================================

func TestU_GetProfileAlgorithm(t *testing.T) {
	t.Run("[Unit] GetProfileAlgorithm: returns valid algorithm", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		alg := GetProfileAlgorithm(prof)
		if alg == "" {
			t.Error("GetProfileAlgorithm() returned empty algorithm")
		}
	})

	t.Run("[Unit] GetProfileAlgorithm: is supported", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		alg := GetProfileAlgorithm(prof)
		if !IsSupportedAlgorithm(alg) {
			t.Errorf("GetProfileAlgorithm() returned unsupported algorithm: %s", alg)
		}
	})
}

// =============================================================================
// GetProfileMode Tests
// =============================================================================

func TestU_GetProfileMode(t *testing.T) {
	t.Run("[Unit] GetProfileMode: returns mode string", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		mode := GetProfileMode(prof)
		// Mode can be empty or a specific value
		validModes := []string{"", "standalone", "csr", "simple"}
		valid := false
		for _, m := range validModes {
			if mode == m {
				valid = true
				break
			}
		}
		if !valid {
			t.Errorf("GetProfileMode() = %s, expected one of %v", mode, validModes)
		}
	})
}

// =============================================================================
// BuildSubjectFromProfile Tests
// =============================================================================

func TestU_BuildSubjectFromProfile(t *testing.T) {
	t.Run("[Unit] BuildSubjectFromProfile: with valid variables", func(t *testing.T) {
		prof, err := LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("LoadProfile() error = %v", err)
		}

		vars := VariableValues{
			"cn":        "test.example.com",
			"dns_names": []string{"test.example.com"},
		}

		subject, err := BuildSubjectFromProfile(prof, vars)
		if err != nil {
			t.Fatalf("BuildSubjectFromProfile() error = %v", err)
		}

		if subject.CommonName != "test.example.com" {
			t.Errorf("BuildSubjectFromProfile() CN = %s, want test.example.com", subject.CommonName)
		}
	})
}

// =============================================================================
// LoadProfileFromBytes Tests
// =============================================================================

func TestU_LoadProfileFromBytes(t *testing.T) {
	t.Run("[Unit] LoadProfileFromBytes: valid YAML", func(t *testing.T) {
		yamlData := []byte(`
name: test-profile
description: Test profile
validity: 8760h
algorithm: ecdsa-p256
subject:
  cn: "{{ cn }}"
`)

		prof, err := LoadProfileFromBytes(yamlData)
		if err != nil {
			t.Fatalf("LoadProfileFromBytes() error = %v", err)
		}

		if prof.Name != "test-profile" {
			t.Errorf("LoadProfileFromBytes() name = %s, want test-profile", prof.Name)
		}
	})

	t.Run("[Unit] LoadProfileFromBytes: invalid YAML", func(t *testing.T) {
		invalidYAML := []byte(`not: valid: yaml: [[[`)

		_, err := LoadProfileFromBytes(invalidYAML)
		if err == nil {
			t.Error("LoadProfileFromBytes() should fail for invalid YAML")
		}
	})
}
