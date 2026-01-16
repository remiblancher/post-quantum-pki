package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// configureHSMKeyProvider configures the CA with an HSM key provider if HSM config is specified.
func configureHSMKeyProvider(caInstance *ca.CA, hsmConfigPath, keyLabel string) error {
	if hsmConfigPath == "" {
		return nil
	}

	hsmCfg, err := pkicrypto.LoadHSMConfig(hsmConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return fmt.Errorf("failed to get HSM PIN: %w", err)
	}

	keyCfg := pkicrypto.KeyStorageConfig{
		Type:           pkicrypto.KeyProviderTypePKCS11,
		PKCS11Lib:      hsmCfg.PKCS11.Lib,
		PKCS11Token:    hsmCfg.PKCS11.Token,
		PKCS11Pin:      pin,
		PKCS11KeyLabel: keyLabel,
	}
	km := pkicrypto.NewKeyProvider(keyCfg)
	caInstance.SetKeyProvider(km, keyCfg)

	return nil
}

// loadEnrollProfiles loads profiles from profile names or file paths.
func loadEnrollProfiles(caDir string, profileNames []string) ([]*profile.Profile, error) {
	// Load profile store
	profileStore := profile.NewProfileStore(caDir)
	if err := profileStore.Load(); err != nil {
		return nil, fmt.Errorf("failed to load profiles: %w", err)
	}

	profiles := make([]*profile.Profile, 0, len(profileNames))
	for _, name := range profileNames {
		var prof *profile.Profile
		var err error

		// Check if it's a file path (contains path separator or ends with .yaml/.yml)
		if strings.Contains(name, string(os.PathSeparator)) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			prof, err = profile.LoadProfile(name)
			if err != nil {
				return nil, fmt.Errorf("failed to load profile from path %s: %w", name, err)
			}
		} else {
			var ok bool
			prof, ok = profileStore.Get(name)
			if !ok {
				return nil, fmt.Errorf("profile not found: %s", name)
			}
		}
		profiles = append(profiles, prof)
	}

	return profiles, nil
}

// resolveProfilesExtensions resolves template variables in profile extensions.
func resolveProfilesExtensions(profiles []*profile.Profile, varValues profile.VariableValues) ([]*profile.Profile, error) {
	result := make([]*profile.Profile, len(profiles))
	copy(result, profiles)

	for i, prof := range profiles {
		resolvedExtensions, err := profile.ResolveProfileExtensions(prof, varValues)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve extensions in profile %s: %w", prof.Name, err)
		}
		if resolvedExtensions != nil {
			profileCopy := *prof
			profileCopy.Extensions = resolvedExtensions
			result[i] = &profileCopy
		}
	}

	return result, nil
}
