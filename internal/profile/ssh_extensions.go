package profile

// SSHExtensionsConfig defines SSH certificate extensions and critical options.
// This is used in SSH profiles (cert_type: ssh) instead of X.509 ExtensionsConfig.
type SSHExtensionsConfig struct {
	// Type is the SSH certificate type: "user" or "host".
	Type string `yaml:"type" json:"type"`

	// CriticalOptions are enforced restrictions on certificate usage.
	CriticalOptions *SSHCriticalOptions `yaml:"critical_options,omitempty" json:"critical_options,omitempty"`

	// Permissions controls which SSH operations are allowed.
	Permissions *SSHPermissions `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// SSHCriticalOptions defines SSH certificate critical options.
// If a client does not recognize a critical option, the certificate is rejected.
type SSHCriticalOptions struct {
	// ForceCommand restricts the certificate to running a single command.
	// Template variables ({{ force_command }}) are supported.
	ForceCommand string `yaml:"force_command,omitempty" json:"force_command,omitempty"`

	// SourceAddress restricts certificate usage to specific IP addresses/CIDRs.
	// Template variables ({{ source_address }}) are supported.
	SourceAddress string `yaml:"source_address,omitempty" json:"source_address,omitempty"`
}

// SSHPermissions defines SSH certificate extension permissions.
// All permissions default to true for user certificates (matching OpenSSH defaults).
// Host certificates have no extensions by default.
type SSHPermissions struct {
	// PermitPTY allows pseudo-terminal allocation. Default: true (user), false (host).
	PermitPTY *bool `yaml:"permit_pty,omitempty" json:"permit_pty,omitempty"`

	// PermitPortForwarding allows port forwarding. Default: true (user), false (host).
	PermitPortForwarding *bool `yaml:"permit_port_forwarding,omitempty" json:"permit_port_forwarding,omitempty"`

	// PermitAgentForwarding allows SSH agent forwarding. Default: true (user), false (host).
	PermitAgentForwarding *bool `yaml:"permit_agent_forwarding,omitempty" json:"permit_agent_forwarding,omitempty"`

	// PermitX11Forwarding allows X11 forwarding. Default: true (user), false (host).
	PermitX11Forwarding *bool `yaml:"permit_x11_forwarding,omitempty" json:"permit_x11_forwarding,omitempty"`

	// PermitUserRC allows execution of ~/.ssh/rc. Default: true (user), false (host).
	PermitUserRC *bool `yaml:"permit_user_rc,omitempty" json:"permit_user_rc,omitempty"`
}

// Validate checks that the SSH extensions configuration is valid.
func (c *SSHExtensionsConfig) Validate() error {
	if c.Type != "user" && c.Type != "host" {
		return &ValidationError{Field: "ssh_extensions.type", Message: "must be 'user' or 'host'"}
	}
	return nil
}

// ToSSHExtensions converts permissions into the map[string]string format used by ssh.Certificate.
func (c *SSHExtensionsConfig) ToSSHExtensions() map[string]string {
	if c.Type == "host" {
		return nil
	}

	exts := make(map[string]string)

	// Default all permissions to true for user certs (OpenSSH behavior)
	permitPTY := true
	permitPortFwd := true
	permitAgentFwd := true
	permitX11 := true
	permitUserRC := true

	if c.Permissions != nil {
		if c.Permissions.PermitPTY != nil {
			permitPTY = *c.Permissions.PermitPTY
		}
		if c.Permissions.PermitPortForwarding != nil {
			permitPortFwd = *c.Permissions.PermitPortForwarding
		}
		if c.Permissions.PermitAgentForwarding != nil {
			permitAgentFwd = *c.Permissions.PermitAgentForwarding
		}
		if c.Permissions.PermitX11Forwarding != nil {
			permitX11 = *c.Permissions.PermitX11Forwarding
		}
		if c.Permissions.PermitUserRC != nil {
			permitUserRC = *c.Permissions.PermitUserRC
		}
	}

	if permitPTY {
		exts["permit-pty"] = ""
	}
	if permitPortFwd {
		exts["permit-port-forwarding"] = ""
	}
	if permitAgentFwd {
		exts["permit-agent-forwarding"] = ""
	}
	if permitX11 {
		exts["permit-X11-forwarding"] = ""
	}
	if permitUserRC {
		exts["permit-user-rc"] = ""
	}

	return exts
}

// ToSSHCriticalOptions converts critical options into the map[string]string format.
func (c *SSHExtensionsConfig) ToSSHCriticalOptions(vars map[string]string) map[string]string {
	if c.CriticalOptions == nil {
		return nil
	}

	opts := make(map[string]string)

	if c.CriticalOptions.ForceCommand != "" {
		val := resolveTemplate(c.CriticalOptions.ForceCommand, vars)
		if val != "" {
			opts["force-command"] = val
		}
	}

	if c.CriticalOptions.SourceAddress != "" {
		val := resolveTemplate(c.CriticalOptions.SourceAddress, vars)
		if val != "" {
			opts["source-address"] = val
		}
	}

	if len(opts) == 0 {
		return nil
	}
	return opts
}

// resolveTemplate replaces {{ var }} placeholders with variable values.
func resolveTemplate(tmpl string, vars map[string]string) string {
	result := tmpl
	for k, v := range vars {
		result = replaceAll(result, "{{ "+k+" }}", v)
		result = replaceAll(result, "{{"+k+"}}", v)
	}
	return result
}

// replaceAll is a simple string replacement without importing strings.
func replaceAll(s, old, new string) string {
	if old == new || old == "" {
		return s
	}
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result = append(result, new...)
			i += len(old)
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return string(result)
}

