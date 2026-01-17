package profile

import (
	"testing"
	"time"
)

func TestValidityTemplate(t *testing.T) {
	t.Run("load profile with validity template", func(t *testing.T) {
		yaml := `
name: test-validity-template
algorithm: ecdsa-p256
variables:
  validity:
    type: duration
    required: true
validity: "{{ validity }}"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		if prof.ValidityTemplate != "{{ validity }}" {
			t.Errorf("expected ValidityTemplate='{{ validity }}', got %q", prof.ValidityTemplate)
		}
		if prof.Validity != 0 {
			t.Errorf("expected Validity=0 for template, got %v", prof.Validity)
		}
	})

	t.Run("load profile with fixed validity", func(t *testing.T) {
		yaml := `
name: test-fixed-validity
algorithm: ecdsa-p256
validity: "365d"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		if prof.ValidityTemplate != "" {
			t.Errorf("expected empty ValidityTemplate for fixed value, got %q", prof.ValidityTemplate)
		}
		expectedValidity := 365 * 24 * time.Hour
		if prof.Validity != expectedValidity {
			t.Errorf("expected Validity=%v, got %v", expectedValidity, prof.Validity)
		}
	})

	t.Run("resolve validity template", func(t *testing.T) {
		yaml := `
name: test-resolve-validity
algorithm: ecdsa-p256
variables:
  validity:
    type: duration
    required: true
validity: "{{ validity }}"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		values := VariableValues{"validity": "30d"}
		validity, err := ResolveProfileValidity(prof, values)
		if err != nil {
			t.Fatalf("unexpected error resolving validity: %v", err)
		}

		expected := 30 * 24 * time.Hour
		if validity != expected {
			t.Errorf("expected validity=%v, got %v", expected, validity)
		}
	})

	t.Run("resolve validity with hours", func(t *testing.T) {
		yaml := `
name: test-resolve-validity-hours
algorithm: ecdsa-p256
variables:
  validity:
    type: duration
validity: "{{ validity }}"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		values := VariableValues{"validity": "720h"}
		validity, err := ResolveProfileValidity(prof, values)
		if err != nil {
			t.Fatalf("unexpected error resolving validity: %v", err)
		}

		expected := 720 * time.Hour
		if validity != expected {
			t.Errorf("expected validity=%v, got %v", expected, validity)
		}
	})

	t.Run("resolve profile without template returns fixed validity", func(t *testing.T) {
		yaml := `
name: test-fixed
algorithm: ecdsa-p256
validity: "365d"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		values := VariableValues{"validity": "30d"} // Should be ignored
		validity, err := ResolveProfileValidity(prof, values)
		if err != nil {
			t.Fatalf("unexpected error resolving validity: %v", err)
		}

		expected := 365 * 24 * time.Hour
		if validity != expected {
			t.Errorf("expected fixed validity=%v, got %v", expected, validity)
		}
	})

	t.Run("missing validity variable returns error", func(t *testing.T) {
		yaml := `
name: test-missing-validity
algorithm: ecdsa-p256
variables:
  validity:
    type: duration
    required: true
validity: "{{ validity }}"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		values := VariableValues{} // No validity provided
		_, err = ResolveProfileValidity(prof, values)
		if err == nil {
			t.Error("expected error for missing validity variable")
		}
	})
}

func TestCDPAIATemplate(t *testing.T) {
	t.Run("substitute CDP URLs", func(t *testing.T) {
		ext := &ExtensionsConfig{
			CRLDistributionPoints: &CRLDistributionPointsConfig{
				URLs: []string{"{{ crl_url }}"},
			},
		}

		vars := map[string][]string{
			"crl_url": {"http://crl.example.com/ca.crl"},
		}

		result, err := ext.SubstituteVariables(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.CRLDistributionPoints.URLs) != 1 {
			t.Fatalf("expected 1 URL, got %d", len(result.CRLDistributionPoints.URLs))
		}
		if result.CRLDistributionPoints.URLs[0] != "http://crl.example.com/ca.crl" {
			t.Errorf("expected http://crl.example.com/ca.crl, got %s", result.CRLDistributionPoints.URLs[0])
		}
	})

	t.Run("substitute AIA URLs", func(t *testing.T) {
		ext := &ExtensionsConfig{
			AuthorityInfoAccess: &AuthorityInfoAccessConfig{
				CAIssuers: []string{"{{ ca_issuer }}"},
				OCSP:      []string{"{{ ocsp_url }}"},
			},
		}

		vars := map[string][]string{
			"ca_issuer": {"http://pki.example.com/ca.crt"},
			"ocsp_url":  {"http://ocsp.example.com"},
		}

		result, err := ext.SubstituteVariables(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.AuthorityInfoAccess.CAIssuers) != 1 {
			t.Fatalf("expected 1 CAIssuer, got %d", len(result.AuthorityInfoAccess.CAIssuers))
		}
		if result.AuthorityInfoAccess.CAIssuers[0] != "http://pki.example.com/ca.crt" {
			t.Errorf("expected http://pki.example.com/ca.crt, got %s", result.AuthorityInfoAccess.CAIssuers[0])
		}

		if len(result.AuthorityInfoAccess.OCSP) != 1 {
			t.Fatalf("expected 1 OCSP, got %d", len(result.AuthorityInfoAccess.OCSP))
		}
		if result.AuthorityInfoAccess.OCSP[0] != "http://ocsp.example.com" {
			t.Errorf("expected http://ocsp.example.com, got %s", result.AuthorityInfoAccess.OCSP[0])
		}
	})

	t.Run("substitute CPS URL", func(t *testing.T) {
		ext := &ExtensionsConfig{
			CertificatePolicies: &CertificatePoliciesConfig{
				Policies: []PolicyConfig{
					{OID: "1.2.3.4", CPS: "{{ cps_url }}"},
				},
			},
		}

		vars := map[string][]string{
			"cps_url": {"https://pki.example.com/cps"},
		}

		result, err := ext.SubstituteVariables(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.CertificatePolicies.Policies) != 1 {
			t.Fatalf("expected 1 policy, got %d", len(result.CertificatePolicies.Policies))
		}
		if result.CertificatePolicies.Policies[0].CPS != "https://pki.example.com/cps" {
			t.Errorf("expected https://pki.example.com/cps, got %s", result.CertificatePolicies.Policies[0].CPS)
		}
	})

	t.Run("mixed static and template values", func(t *testing.T) {
		ext := &ExtensionsConfig{
			CRLDistributionPoints: &CRLDistributionPointsConfig{
				URLs: []string{
					"http://static.example.com/ca.crl",
					"{{ crl_url }}",
				},
			},
			AuthorityInfoAccess: &AuthorityInfoAccessConfig{
				OCSP: []string{"http://static-ocsp.example.com"},
			},
		}

		vars := map[string][]string{
			"crl_url": {"http://dynamic.example.com/ca.crl"},
		}

		result, err := ext.SubstituteVariables(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check CDP - should have both static and resolved
		if len(result.CRLDistributionPoints.URLs) != 2 {
			t.Fatalf("expected 2 URLs, got %d", len(result.CRLDistributionPoints.URLs))
		}
		if result.CRLDistributionPoints.URLs[0] != "http://static.example.com/ca.crl" {
			t.Errorf("expected static URL preserved, got %s", result.CRLDistributionPoints.URLs[0])
		}
		if result.CRLDistributionPoints.URLs[1] != "http://dynamic.example.com/ca.crl" {
			t.Errorf("expected dynamic URL substituted, got %s", result.CRLDistributionPoints.URLs[1])
		}

		// Check AIA - should preserve static value
		if len(result.AuthorityInfoAccess.OCSP) != 1 {
			t.Fatalf("expected 1 OCSP URL, got %d", len(result.AuthorityInfoAccess.OCSP))
		}
		if result.AuthorityInfoAccess.OCSP[0] != "http://static-ocsp.example.com" {
			t.Errorf("expected static OCSP preserved, got %s", result.AuthorityInfoAccess.OCSP[0])
		}
	})

	t.Run("missing variable removes from list", func(t *testing.T) {
		ext := &ExtensionsConfig{
			CRLDistributionPoints: &CRLDistributionPointsConfig{
				URLs: []string{"{{ missing_var }}"},
			},
		}

		vars := map[string][]string{} // No variables provided

		result, err := ext.SubstituteVariables(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.CRLDistributionPoints.URLs) != 0 {
			t.Errorf("expected empty URLs for missing variable, got %v", result.CRLDistributionPoints.URLs)
		}
	})
}

func TestExtractTemplateVariables(t *testing.T) {
	t.Run("extract SAN and CDP/AIA variables", func(t *testing.T) {
		vars := VariableValues{
			"dns_names":    []string{"a.com", "b.com"},
			"ip_addresses": []string{"192.168.1.1"},
			"email":        []string{"admin@example.com"},
			"crl_url":      "http://crl.example.com/ca.crl",
			"ca_issuer":    "http://pki.example.com/ca.crt",
			"ocsp_url":     "http://ocsp.example.com",
			"cps_url":      "https://pki.example.com/cps",
		}

		result := ExtractTemplateVariables(vars)

		// Check SAN variables
		if len(result["dns_names"]) != 2 {
			t.Errorf("expected 2 dns_names, got %v", result["dns_names"])
		}
		if len(result["ip_addresses"]) != 1 {
			t.Errorf("expected 1 ip_addresses, got %v", result["ip_addresses"])
		}
		if len(result["email"]) != 1 {
			t.Errorf("expected 1 email, got %v", result["email"])
		}

		// Check CDP/AIA/CPS variables
		if len(result["crl_url"]) != 1 || result["crl_url"][0] != "http://crl.example.com/ca.crl" {
			t.Errorf("expected crl_url, got %v", result["crl_url"])
		}
		if len(result["ca_issuer"]) != 1 || result["ca_issuer"][0] != "http://pki.example.com/ca.crt" {
			t.Errorf("expected ca_issuer, got %v", result["ca_issuer"])
		}
		if len(result["ocsp_url"]) != 1 || result["ocsp_url"][0] != "http://ocsp.example.com" {
			t.Errorf("expected ocsp_url, got %v", result["ocsp_url"])
		}
		if len(result["cps_url"]) != 1 || result["cps_url"][0] != "https://pki.example.com/cps" {
			t.Errorf("expected cps_url, got %v", result["cps_url"])
		}
	})

	t.Run("partial variables", func(t *testing.T) {
		vars := VariableValues{
			"crl_url": "http://crl.example.com/ca.crl",
		}

		result := ExtractTemplateVariables(vars)

		if len(result["crl_url"]) != 1 {
			t.Errorf("expected crl_url, got %v", result["crl_url"])
		}
		if _, exists := result["ocsp_url"]; exists {
			t.Error("ocsp_url should not be in result")
		}
	})
}

func TestProfileToYAMLWithValidityTemplate(t *testing.T) {
	t.Run("preserve validity template in YAML output", func(t *testing.T) {
		yaml := `
name: test-yaml-output
algorithm: ecdsa-p256
variables:
  validity:
    type: duration
validity: "{{ validity }}"
extensions:
  keyUsage:
    values: [digitalSignature]
`
		prof, err := LoadProfileFromBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error loading profile: %v", err)
		}

		py := ProfileToYAML(prof)

		if py.Validity != "{{ validity }}" {
			t.Errorf("expected Validity='{{ validity }}', got %q", py.Validity)
		}
	})
}
