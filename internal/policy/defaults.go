package policy

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed defaults/*.yaml
var defaultGammesFS embed.FS

// DefaultGammes returns the predefined gammes.
// These are compiled into the binary and serve as templates.
func DefaultGammes() (map[string]*Gamme, error) {
	gammes := make(map[string]*Gamme)

	entries, err := defaultGammesFS.ReadDir("defaults")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded defaults: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := defaultGammesFS.ReadFile("defaults/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", entry.Name(), err)
		}

		gamme, err := LoadGammeFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", entry.Name(), err)
		}

		gammes[gamme.Name] = gamme
	}

	return gammes, nil
}

// InstallDefaultGammes copies the default gammes to the CA's gammes directory.
// If overwrite is false, existing files are not replaced.
func InstallDefaultGammes(caPath string, overwrite bool) error {
	gammesDir := filepath.Join(caPath, "gammes")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(gammesDir, 0755); err != nil {
		return fmt.Errorf("failed to create gammes directory: %w", err)
	}

	// Walk through embedded files
	err := fs.WalkDir(defaultGammesFS, "defaults", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Read embedded file
		data, err := defaultGammesFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		// Destination path
		destPath := filepath.Join(gammesDir, d.Name())

		// Check if file exists
		if !overwrite {
			if _, err := os.Stat(destPath); err == nil {
				// File exists, skip
				return nil
			}
		}

		// Write file
		if err := os.WriteFile(destPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", destPath, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to install default gammes: %w", err)
	}

	return nil
}

// ListDefaultGammeNames returns the names of all default gammes.
func ListDefaultGammeNames() ([]string, error) {
	entries, err := defaultGammesFS.ReadDir("defaults")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded defaults: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Parse to get the name
		data, err := defaultGammesFS.ReadFile("defaults/" + entry.Name())
		if err != nil {
			continue
		}

		gamme, err := LoadGammeFromBytes(data)
		if err != nil {
			continue
		}

		names = append(names, gamme.Name)
	}

	return names, nil
}

// GetDefaultGamme returns a specific default gamme by name.
func GetDefaultGamme(name string) (*Gamme, error) {
	gammes, err := DefaultGammes()
	if err != nil {
		return nil, err
	}

	gamme, ok := gammes[name]
	if !ok {
		return nil, fmt.Errorf("default gamme not found: %s", name)
	}

	return gamme, nil
}
