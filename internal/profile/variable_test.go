package profile

import (
	"testing"
)

func TestVariableValidator_String(t *testing.T) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
			Pattern:  `^[a-zA-Z0-9][a-zA-Z0-9.-]+$`,
		},
		"country": {
			Name:      "country",
			Type:      VarTypeString,
			Required:  false,
			Default:   "FR",
			Pattern:   `^[A-Z]{2}$`,
			MinLength: 2,
			MaxLength: 2,
		},
		"env": {
			Name:    "env",
			Type:    VarTypeString,
			Default: "production",
			Enum:    []string{"dev", "staging", "production"},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		varName string
		value   interface{}
		wantErr bool
	}{
		{"valid cn", "cn", "api.example.com", false},
		{"invalid cn pattern", "cn", "-invalid", true},
		{"valid country", "country", "US", false},
		{"invalid country pattern", "country", "USA", true},
		{"invalid country length", "country", "U", true},
		{"valid env", "env", "staging", false},
		{"invalid env enum", "env", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.varName, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_Integer(t *testing.T) {
	min := 1
	max := 825

	vars := map[string]*Variable{
		"validity_days": {
			Name:     "validity_days",
			Type:     VarTypeInteger,
			Required: false,
			Default:  365,
			Min:      &min,
			Max:      &max,
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid 365", 365, false},
		{"valid 1", 1, false},
		{"valid 825", 825, false},
		{"below min", 0, true},
		{"above max", 1000, true},
		{"float64", float64(100), false}, // JSON/YAML decode as float64
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("validity_days", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_List(t *testing.T) {
	vars := map[string]*Variable{
		"dns_names": {
			Name:     "dns_names",
			Type:     VarTypeList,
			Required: false,
			Default:  []string{},
			Constraints: &ListConstraints{
				AllowedSuffixes: []string{".example.com", ".internal"},
				DeniedPrefixes:  []string{"test-"},
				MaxItems:        5,
			},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid single", []string{"api.example.com"}, false},
		{"valid multiple", []string{"api.example.com", "db.internal"}, false},
		{"invalid suffix", []string{"api.other.com"}, true},
		{"denied prefix", []string{"test-api.example.com"}, true},
		{"too many items", []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com"}, true},
		{"empty list", []string{}, false},
		{"interface list", []interface{}{"api.example.com"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("dns_names", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_IPList(t *testing.T) {
	vars := map[string]*Variable{
		"ip_addresses": {
			Name:     "ip_addresses",
			Type:     VarTypeIPList,
			Required: false,
			Constraints: &ListConstraints{
				AllowedRanges: []string{"10.0.0.0/8", "192.168.0.0/16"},
				MaxItems:      3,
			},
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{"valid 10.x", []string{"10.0.0.1"}, false},
		{"valid 192.168.x", []string{"192.168.1.1"}, false},
		{"valid multiple", []string{"10.0.0.1", "192.168.1.1"}, false},
		{"outside range", []string{"8.8.8.8"}, true},
		{"invalid IP", []string{"not-an-ip"}, true},
		{"too many IPs", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, true},
		{"empty list", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate("ip_addresses", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_ValidateAll(t *testing.T) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
		},
		"org": {
			Name:    "org",
			Type:    VarTypeString,
			Default: "ACME Corp",
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		values  VariableValues
		wantErr bool
	}{
		{
			"all provided",
			VariableValues{"cn": "test.example.com", "org": "Test Inc"},
			false,
		},
		{
			"required only",
			VariableValues{"cn": "test.example.com"},
			false,
		},
		{
			"missing required",
			VariableValues{"org": "Test Inc"},
			true,
		},
		{
			"empty",
			VariableValues{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateAll(tt.values)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAll() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVariableValidator_MergeWithDefaults(t *testing.T) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
		},
		"org": {
			Name:    "org",
			Type:    VarTypeString,
			Default: "ACME Corp",
		},
		"country": {
			Name:    "country",
			Type:    VarTypeString,
			Default: "FR",
		},
	}

	v, err := NewVariableValidator(vars)
	if err != nil {
		t.Fatalf("NewVariableValidator failed: %v", err)
	}

	userValues := VariableValues{
		"cn":  "test.example.com",
		"org": "Custom Org",
	}

	merged := v.MergeWithDefaults(userValues)

	// Check user value preserved
	if cn, ok := merged.GetString("cn"); !ok || cn != "test.example.com" {
		t.Errorf("cn = %q, want %q", cn, "test.example.com")
	}

	// Check user override
	if org, ok := merged.GetString("org"); !ok || org != "Custom Org" {
		t.Errorf("org = %q, want %q", org, "Custom Org")
	}

	// Check default used
	if country, ok := merged.GetString("country"); !ok || country != "FR" {
		t.Errorf("country = %q, want %q", country, "FR")
	}
}

func TestParseVarFlags(t *testing.T) {
	tests := []struct {
		name    string
		flags   []string
		want    VariableValues
		wantErr bool
	}{
		{
			"single value",
			[]string{"cn=api.example.com"},
			VariableValues{"cn": "api.example.com"},
			false,
		},
		{
			"list value",
			[]string{"dns_names=a.example.com,b.example.com"},
			VariableValues{"dns_names": []string{"a.example.com", "b.example.com"}},
			false,
		},
		{
			"multiple flags",
			[]string{"cn=api.example.com", "env=production"},
			VariableValues{"cn": "api.example.com", "env": "production"},
			false,
		},
		{
			"invalid format",
			[]string{"invalid"},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVarFlags(tt.flags)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVarFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			for key, wantVal := range tt.want {
				gotVal, ok := got[key]
				if !ok {
					t.Errorf("missing key %q", key)
					continue
				}

				switch w := wantVal.(type) {
				case string:
					if g, ok := gotVal.(string); !ok || g != w {
						t.Errorf("got[%q] = %v, want %v", key, gotVal, wantVal)
					}
				case []string:
					if g, ok := gotVal.([]string); !ok || len(g) != len(w) {
						t.Errorf("got[%q] = %v, want %v", key, gotVal, wantVal)
					}
				}
			}
		})
	}
}

func TestTemplateEngine_SubstituteString(t *testing.T) {
	profile := &Profile{
		Name:      "test",
		Algorithm: "ecdsa-p256",
		Variables: map[string]*Variable{
			"cn": {
				Name:     "cn",
				Type:     VarTypeString,
				Required: true,
			},
			"days": {
				Name:    "days",
				Type:    VarTypeInteger,
				Default: 365,
			},
		},
	}

	engine, err := NewTemplateEngine(profile)
	if err != nil {
		t.Fatalf("NewTemplateEngine failed: %v", err)
	}

	values := VariableValues{
		"cn":   "api.example.com",
		"days": 730,
	}

	tests := []struct {
		name     string
		template string
		want     string
		wantErr  bool
	}{
		{"simple", "{{ cn }}", "api.example.com", false},
		{"with spaces", "{{  cn  }}", "api.example.com", false},
		{"integer", "{{ days }}", "730", false},
		{"mixed", "CN={{ cn }}, days={{ days }}", "CN=api.example.com, days=730", false},
		{"missing var", "{{ unknown }}", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := engine.SubstituteString(tt.template, values)
			if (err != nil) != tt.wantErr {
				t.Errorf("SubstituteString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SubstituteString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Benchmarks

func BenchmarkVariableValidator_Validate(b *testing.B) {
	vars := map[string]*Variable{
		"cn": {
			Name:     "cn",
			Type:     VarTypeString,
			Required: true,
			Pattern:  `^[a-zA-Z0-9][a-zA-Z0-9.-]+$`,
		},
	}

	v, _ := NewVariableValidator(vars)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Validate("cn", "api.example.com")
	}
}

func BenchmarkVariableValidator_ValidateList(b *testing.B) {
	vars := map[string]*Variable{
		"dns_names": {
			Name: "dns_names",
			Type: VarTypeList,
			Constraints: &ListConstraints{
				AllowedSuffixes: []string{".example.com", ".internal"},
				MaxItems:        10,
			},
		},
	}

	v, _ := NewVariableValidator(vars)
	list := []string{"api.example.com", "db.example.com", "cache.internal"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Validate("dns_names", list)
	}
}

func BenchmarkParseVarFlags(b *testing.B) {
	flags := []string{
		"cn=api.example.com",
		"dns_names=a.example.com,b.example.com,c.example.com",
		"env=production",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseVarFlags(flags)
	}
}
