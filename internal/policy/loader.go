package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/remiblancher/pki/internal/crypto"
	"gopkg.in/yaml.v3"
)

// gammeYAML is the YAML representation of a Gamme.
// It uses string duration for easier human editing.
type gammeYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	Signature struct {
		Required   bool   `yaml:"required"`
		Mode       string `yaml:"mode"`
		Algorithms struct {
			Primary     string `yaml:"primary"`
			Alternative string `yaml:"alternative,omitempty"`
		} `yaml:"algorithms"`
	} `yaml:"signature"`

	Encryption struct {
		Required   bool   `yaml:"required"`
		Mode       string `yaml:"mode"`
		Algorithms struct {
			Primary     string `yaml:"primary,omitempty"`
			Alternative string `yaml:"alternative,omitempty"`
		} `yaml:"algorithms"`
	} `yaml:"encryption"`

	Validity string `yaml:"validity"` // Duration string like "8760h" or "365d"
}

// LoadGammeFromFile loads a gamme from a YAML file.
func LoadGammeFromFile(path string) (*Gamme, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read gamme file: %w", err)
	}

	return LoadGammeFromBytes(data)
}

// LoadGammeFromBytes loads a gamme from YAML bytes.
func LoadGammeFromBytes(data []byte) (*Gamme, error) {
	var gy gammeYAML
	if err := yaml.Unmarshal(data, &gy); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return gammeYAMLToGamme(&gy)
}

// gammeYAMLToGamme converts the YAML representation to a Gamme.
func gammeYAMLToGamme(gy *gammeYAML) (*Gamme, error) {
	g := &Gamme{
		Name:        gy.Name,
		Description: gy.Description,
	}

	// Parse signature config
	g.Signature.Required = gy.Signature.Required
	g.Signature.Mode = SignatureMode(gy.Signature.Mode)
	g.Signature.Algorithms.Primary = parseAlgorithmID(gy.Signature.Algorithms.Primary)
	g.Signature.Algorithms.Alternative = parseAlgorithmID(gy.Signature.Algorithms.Alternative)

	// Parse encryption config
	g.Encryption.Required = gy.Encryption.Required
	g.Encryption.Mode = EncryptionMode(gy.Encryption.Mode)
	g.Encryption.Algorithms.Primary = parseAlgorithmID(gy.Encryption.Algorithms.Primary)
	g.Encryption.Algorithms.Alternative = parseAlgorithmID(gy.Encryption.Algorithms.Alternative)

	// Parse validity duration
	validity, err := parseDuration(gy.Validity)
	if err != nil {
		return nil, fmt.Errorf("invalid validity: %w", err)
	}
	g.Validity = validity

	// Validate the gamme
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("gamme validation failed: %w", err)
	}

	return g, nil
}

// parseAlgorithmID converts a string to an AlgorithmID.
// Accepts various formats: "ecdsa-p256", "ECDSA-P256", "ml-dsa-65", etc.
func parseAlgorithmID(s string) crypto.AlgorithmID {
	if s == "" {
		return ""
	}
	return crypto.AlgorithmID(s)
}

// parseDuration parses a duration string that can include days.
// Supported formats: "8760h", "365d", "1y", "30d12h"
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("duration is empty")
	}

	// Try standard Go duration first
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle custom formats with days/years
	var total time.Duration
	remaining := s

	// Parse years
	if idx := findSuffix(remaining, "y"); idx >= 0 {
		years, err := parseInt(remaining[:idx])
		if err != nil {
			return 0, fmt.Errorf("invalid years: %w", err)
		}
		total += time.Duration(years) * 365 * 24 * time.Hour
		remaining = remaining[idx+1:]
	}

	// Parse days
	if idx := findSuffix(remaining, "d"); idx >= 0 {
		days, err := parseInt(remaining[:idx])
		if err != nil {
			return 0, fmt.Errorf("invalid days: %w", err)
		}
		total += time.Duration(days) * 24 * time.Hour
		remaining = remaining[idx+1:]
	}

	// Parse remaining as standard duration
	if remaining != "" {
		d, err := time.ParseDuration(remaining)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %w", err)
		}
		total += d
	}

	return total, nil
}

func findSuffix(s, suffix string) int {
	for i := 0; i < len(s); i++ {
		if s[i:i+1] == suffix {
			return i
		}
	}
	return -1
}

func parseInt(s string) (int, error) {
	var n int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number: %s", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// LoadGammesFromDirectory loads all gammes from a directory.
// Returns a map of gamme name to Gamme.
func LoadGammesFromDirectory(dir string) (map[string]*Gamme, error) {
	gammes := make(map[string]*Gamme)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return gammes, nil // Empty directory is OK
		}
		return nil, fmt.Errorf("failed to read gammes directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml" {
			continue
		}

		path := filepath.Join(dir, name)
		gamme, err := LoadGammeFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load gamme from %s: %w", name, err)
		}

		if _, exists := gammes[gamme.Name]; exists {
			return nil, fmt.Errorf("duplicate gamme name: %s", gamme.Name)
		}

		gammes[gamme.Name] = gamme
	}

	return gammes, nil
}

// SaveGammeToFile saves a gamme to a YAML file.
func SaveGammeToFile(g *Gamme, path string) error {
	gy := gammeToYAML(g)

	data, err := yaml.Marshal(gy)
	if err != nil {
		return fmt.Errorf("failed to marshal gamme: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write gamme file: %w", err)
	}

	return nil
}

// gammeToYAML converts a Gamme to its YAML representation.
func gammeToYAML(g *Gamme) *gammeYAML {
	gy := &gammeYAML{
		Name:        g.Name,
		Description: g.Description,
	}

	gy.Signature.Required = g.Signature.Required
	gy.Signature.Mode = string(g.Signature.Mode)
	gy.Signature.Algorithms.Primary = string(g.Signature.Algorithms.Primary)
	gy.Signature.Algorithms.Alternative = string(g.Signature.Algorithms.Alternative)

	gy.Encryption.Required = g.Encryption.Required
	gy.Encryption.Mode = string(g.Encryption.Mode)
	gy.Encryption.Algorithms.Primary = string(g.Encryption.Algorithms.Primary)
	gy.Encryption.Algorithms.Alternative = string(g.Encryption.Algorithms.Alternative)

	// Format validity as hours or days
	hours := int(g.Validity.Hours())
	if hours%24 == 0 && hours >= 24 {
		gy.Validity = fmt.Sprintf("%dd", hours/24)
	} else {
		gy.Validity = g.Validity.String()
	}

	return gy
}

// GammeStore provides access to gammes for a CA.
type GammeStore struct {
	basePath string
	gammes   map[string]*Gamme
}

// NewGammeStore creates a new GammeStore for the given CA path.
func NewGammeStore(caPath string) *GammeStore {
	return &GammeStore{
		basePath: filepath.Join(caPath, "gammes"),
		gammes:   make(map[string]*Gamme),
	}
}

// Load loads all gammes from the CA's gammes directory.
func (gs *GammeStore) Load() error {
	gammes, err := LoadGammesFromDirectory(gs.basePath)
	if err != nil {
		return err
	}
	gs.gammes = gammes
	return nil
}

// Get returns a gamme by name.
func (gs *GammeStore) Get(name string) (*Gamme, bool) {
	g, ok := gs.gammes[name]
	return g, ok
}

// List returns all loaded gamme names.
func (gs *GammeStore) List() []string {
	names := make([]string, 0, len(gs.gammes))
	for name := range gs.gammes {
		names = append(names, name)
	}
	return names
}

// All returns all loaded gammes.
func (gs *GammeStore) All() map[string]*Gamme {
	return gs.gammes
}

// Save saves a gamme to the CA's gammes directory.
func (gs *GammeStore) Save(g *Gamme) error {
	// Ensure directory exists
	if err := os.MkdirAll(gs.basePath, 0755); err != nil {
		return fmt.Errorf("failed to create gammes directory: %w", err)
	}

	path := filepath.Join(gs.basePath, g.Name+".yaml")
	if err := SaveGammeToFile(g, path); err != nil {
		return err
	}

	gs.gammes[g.Name] = g
	return nil
}

// BasePath returns the gammes directory path.
func (gs *GammeStore) BasePath() string {
	return gs.basePath
}
