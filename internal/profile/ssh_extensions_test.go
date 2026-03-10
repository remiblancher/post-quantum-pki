package profile

import (
	"testing"
)

func TestSSHExtensionsConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SSHExtensionsConfig
		wantErr bool
	}{
		{"valid user", SSHExtensionsConfig{Type: "user"}, false},
		{"valid host", SSHExtensionsConfig{Type: "host"}, false},
		{"invalid type", SSHExtensionsConfig{Type: "bogus"}, true},
		{"empty type", SSHExtensionsConfig{Type: ""}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if _, ok := err.(*ValidationError); !ok {
					t.Errorf("Validate() returned %T, want *ValidationError", err)
				}
			}
		})
	}
}

func TestToSSHExtensionsUserDefaults(t *testing.T) {
	cfg := &SSHExtensionsConfig{Type: "user"}
	exts := cfg.ToSSHExtensions()

	expected := []string{
		"permit-pty",
		"permit-port-forwarding",
		"permit-agent-forwarding",
		"permit-X11-forwarding",
		"permit-user-rc",
	}

	for _, key := range expected {
		if _, ok := exts[key]; !ok {
			t.Errorf("missing default extension: %s", key)
		}
	}

	if len(exts) != len(expected) {
		t.Errorf("len(exts) = %d, want %d", len(exts), len(expected))
	}
}

func TestToSSHExtensionsUserCustom(t *testing.T) {
	f := false
	tr := true
	cfg := &SSHExtensionsConfig{
		Type: "user",
		Permissions: &SSHPermissions{
			PermitPTY:             &tr,
			PermitPortForwarding:  &f,
			PermitAgentForwarding: &f,
			PermitX11Forwarding:   &f,
			PermitUserRC:          &f,
		},
	}
	exts := cfg.ToSSHExtensions()

	if _, ok := exts["permit-pty"]; !ok {
		t.Error("permit-pty should be present")
	}
	if _, ok := exts["permit-port-forwarding"]; ok {
		t.Error("permit-port-forwarding should NOT be present")
	}
	if _, ok := exts["permit-agent-forwarding"]; ok {
		t.Error("permit-agent-forwarding should NOT be present")
	}
	if _, ok := exts["permit-X11-forwarding"]; ok {
		t.Error("permit-X11-forwarding should NOT be present")
	}
	if _, ok := exts["permit-user-rc"]; ok {
		t.Error("permit-user-rc should NOT be present")
	}
}

func TestToSSHExtensionsHost(t *testing.T) {
	cfg := &SSHExtensionsConfig{Type: "host"}
	exts := cfg.ToSSHExtensions()
	if exts != nil {
		t.Errorf("host extensions should be nil, got %v", exts)
	}
}

func TestToSSHCriticalOptionsNil(t *testing.T) {
	cfg := &SSHExtensionsConfig{Type: "user"}
	opts := cfg.ToSSHCriticalOptions(nil)
	if opts != nil {
		t.Errorf("should return nil when CriticalOptions is nil, got %v", opts)
	}
}

func TestToSSHCriticalOptionsForceCommand(t *testing.T) {
	cfg := &SSHExtensionsConfig{
		Type: "user",
		CriticalOptions: &SSHCriticalOptions{
			ForceCommand: "/usr/bin/git-shell",
		},
	}
	opts := cfg.ToSSHCriticalOptions(nil)
	if opts["force-command"] != "/usr/bin/git-shell" {
		t.Errorf("force-command = %s, want /usr/bin/git-shell", opts["force-command"])
	}
}

func TestToSSHCriticalOptionsSourceAddress(t *testing.T) {
	cfg := &SSHExtensionsConfig{
		Type: "user",
		CriticalOptions: &SSHCriticalOptions{
			SourceAddress: "10.0.0.0/8,192.168.1.0/24",
		},
	}
	opts := cfg.ToSSHCriticalOptions(nil)
	if opts["source-address"] != "10.0.0.0/8,192.168.1.0/24" {
		t.Errorf("source-address = %s, want 10.0.0.0/8,192.168.1.0/24", opts["source-address"])
	}
}

func TestToSSHCriticalOptionsTemplateResolution(t *testing.T) {
	cfg := &SSHExtensionsConfig{
		Type: "user",
		CriticalOptions: &SSHCriticalOptions{
			ForceCommand:  "{{ force_command }}",
			SourceAddress: "{{source_address}}",
		},
	}
	vars := map[string]string{
		"force_command":  "/bin/deploy",
		"source_address": "10.0.0.1/32",
	}
	opts := cfg.ToSSHCriticalOptions(vars)
	if opts["force-command"] != "/bin/deploy" {
		t.Errorf("force-command = %s, want /bin/deploy", opts["force-command"])
	}
	if opts["source-address"] != "10.0.0.1/32" {
		t.Errorf("source-address = %s, want 10.0.0.1/32", opts["source-address"])
	}
}

func TestToSSHCriticalOptionsEmptyAfterResolve(t *testing.T) {
	cfg := &SSHExtensionsConfig{
		Type: "user",
		CriticalOptions: &SSHCriticalOptions{
			ForceCommand: "",
		},
	}
	opts := cfg.ToSSHCriticalOptions(nil)
	if opts != nil {
		t.Errorf("should return nil for empty critical options, got %v", opts)
	}
}

func TestResolveTemplate(t *testing.T) {
	tests := []struct {
		tmpl string
		vars map[string]string
		want string
	}{
		{"{{ name }}", map[string]string{"name": "alice"}, "alice"},
		{"{{name}}", map[string]string{"name": "alice"}, "alice"},
		{"hello {{ name }}, you are {{ role }}", map[string]string{"name": "alice", "role": "admin"}, "hello alice, you are admin"},
		{"no vars here", nil, "no vars here"},
		{"{{ missing }}", map[string]string{}, "{{ missing }}"},
	}

	for _, tt := range tests {
		t.Run(tt.tmpl, func(t *testing.T) {
			got := resolveTemplate(tt.tmpl, tt.vars)
			if got != tt.want {
				t.Errorf("resolveTemplate(%q) = %q, want %q", tt.tmpl, got, tt.want)
			}
		})
	}
}

func TestReplaceAll(t *testing.T) {
	tests := []struct {
		s, old, new, want string
	}{
		{"hello world", "world", "Go", "hello Go"},
		{"aaa", "a", "bb", "bbbbbb"},
		{"", "a", "b", ""},
		{"hello", "", "x", "hello"},       // empty old → no-op
		{"hello", "hello", "hello", "hello"}, // same old/new → no-op
	}

	for _, tt := range tests {
		got := replaceAll(tt.s, tt.old, tt.new)
		if got != tt.want {
			t.Errorf("replaceAll(%q, %q, %q) = %q, want %q", tt.s, tt.old, tt.new, got, tt.want)
		}
	}
}
