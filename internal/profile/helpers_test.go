package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadVariables(t *testing.T) {
	t.Run("empty inputs", func(t *testing.T) {
		values, err := LoadVariables("", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(values) != 0 {
			t.Errorf("expected empty map, got %v", values)
		}
	})

	t.Run("flags only", func(t *testing.T) {
		flags := []string{"cn=example.com", "dns_names=a.com,b.com"}
		values, err := LoadVariables("", flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cn, ok := values.GetString("cn"); !ok || cn != "example.com" {
			t.Errorf("expected cn=example.com, got %v", values["cn"])
		}

		dns, ok := values.GetStringList("dns_names")
		if !ok || len(dns) != 2 {
			t.Errorf("expected dns_names list with 2 items, got %v", values["dns_names"])
		}
	})

	t.Run("file only", func(t *testing.T) {
		// Create temp file
		tmpDir := t.TempDir()
		varFile := filepath.Join(tmpDir, "vars.yaml")
		content := `
cn: test.example.com
organization: Test Org
dns_names:
  - test.example.com
  - www.test.example.com
`
		if err := os.WriteFile(varFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		values, err := LoadVariables(varFile, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cn, ok := values.GetString("cn"); !ok || cn != "test.example.com" {
			t.Errorf("expected cn=test.example.com, got %v", values["cn"])
		}

		if o, ok := values.GetString("organization"); !ok || o != "Test Org" {
			t.Errorf("expected organization=Test Org, got %v", values["organization"])
		}
	})

	t.Run("flags override file", func(t *testing.T) {
		// Create temp file
		tmpDir := t.TempDir()
		varFile := filepath.Join(tmpDir, "vars.yaml")
		content := `
cn: from-file.com
organization: File Org
`
		if err := os.WriteFile(varFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		flags := []string{"cn=from-flag.com"}
		values, err := LoadVariables(varFile, flags)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Flag should override file
		if cn, ok := values.GetString("cn"); !ok || cn != "from-flag.com" {
			t.Errorf("expected cn=from-flag.com (from flag), got %v", values["cn"])
		}

		// File value should remain
		if o, ok := values.GetString("organization"); !ok || o != "File Org" {
			t.Errorf("expected organization=File Org (from file), got %v", values["organization"])
		}
	})

	t.Run("invalid file path", func(t *testing.T) {
		_, err := LoadVariables("/nonexistent/path/vars.yaml", nil)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		varFile := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(varFile, []byte("invalid: yaml: content: ["), 0644); err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}

		_, err := LoadVariables(varFile, nil)
		if err == nil {
			t.Error("expected error for invalid yaml")
		}
	})
}

func TestBuildSubject(t *testing.T) {
	t.Run("cn only", func(t *testing.T) {
		vars := VariableValues{"cn": "example.com"}
		subject, err := BuildSubject(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if subject.CommonName != "example.com" {
			t.Errorf("expected CN=example.com, got %s", subject.CommonName)
		}
	})

	t.Run("full subject with short aliases", func(t *testing.T) {
		vars := VariableValues{
			"cn": "example.com",
			"o":  "Example Org",
			"ou": "IT",
			"c":  "US",
			"st": "California",
			"l":  "San Francisco",
		}
		subject, err := BuildSubject(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if subject.CommonName != "example.com" {
			t.Errorf("expected CN=example.com, got %s", subject.CommonName)
		}
		if len(subject.Organization) != 1 || subject.Organization[0] != "Example Org" {
			t.Errorf("expected O=Example Org, got %v", subject.Organization)
		}
		if len(subject.OrganizationalUnit) != 1 || subject.OrganizationalUnit[0] != "IT" {
			t.Errorf("expected OU=IT, got %v", subject.OrganizationalUnit)
		}
		if len(subject.Country) != 1 || subject.Country[0] != "US" {
			t.Errorf("expected C=US, got %v", subject.Country)
		}
		if len(subject.Province) != 1 || subject.Province[0] != "California" {
			t.Errorf("expected ST=California, got %v", subject.Province)
		}
		if len(subject.Locality) != 1 || subject.Locality[0] != "San Francisco" {
			t.Errorf("expected L=San Francisco, got %v", subject.Locality)
		}
	})

	t.Run("full subject with long aliases", func(t *testing.T) {
		vars := VariableValues{
			"cn":           "example.com",
			"organization": "Example Org",
			"country":      "FR",
			"state":        "Île-de-France",
			"locality":     "Paris",
		}
		subject, err := BuildSubject(vars)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(subject.Organization) != 1 || subject.Organization[0] != "Example Org" {
			t.Errorf("expected organization=Example Org, got %v", subject.Organization)
		}
		if len(subject.Country) != 1 || subject.Country[0] != "FR" {
			t.Errorf("expected country=FR, got %v", subject.Country)
		}
	})

	t.Run("missing cn", func(t *testing.T) {
		vars := VariableValues{"o": "Example Org"}
		_, err := BuildSubject(vars)
		if err == nil {
			t.Error("expected error for missing CN")
		}
	})

	t.Run("empty vars", func(t *testing.T) {
		vars := VariableValues{}
		_, err := BuildSubject(vars)
		if err == nil {
			t.Error("expected error for empty vars")
		}
	})
}

func TestExtractTemplateVariables_SAN(t *testing.T) {
	t.Run("all SAN types", func(t *testing.T) {
		vars := VariableValues{
			"dns_names":    []string{"a.com", "b.com"},
			"ip_addresses": []string{"192.168.1.1", "10.0.0.1"},
			"email":        []string{"admin@example.com"},
		}

		result := ExtractTemplateVariables(vars)

		if len(result["dns_names"]) != 2 {
			t.Errorf("expected 2 dns_names, got %v", result["dns_names"])
		}
		if len(result["ip_addresses"]) != 2 {
			t.Errorf("expected 2 ip_addresses, got %v", result["ip_addresses"])
		}
		if len(result["email"]) != 1 {
			t.Errorf("expected 1 email, got %v", result["email"])
		}
	})

	t.Run("partial SANs", func(t *testing.T) {
		vars := VariableValues{
			"dns_names": []string{"example.com"},
			"cn":        "example.com", // Should be ignored
		}

		result := ExtractTemplateVariables(vars)

		if len(result["dns_names"]) != 1 {
			t.Errorf("expected 1 dns_names, got %v", result["dns_names"])
		}
		if _, exists := result["ip_addresses"]; exists {
			t.Error("ip_addresses should not be in result")
		}
		if _, exists := result["cn"]; exists {
			t.Error("cn should not be in result")
		}
	})

	t.Run("empty vars", func(t *testing.T) {
		vars := VariableValues{}
		result := ExtractTemplateVariables(vars)

		if len(result) != 0 {
			t.Errorf("expected empty result, got %v", result)
		}
	})
}
