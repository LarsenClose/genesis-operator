package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type SOPSConfig struct {
	CreationRules []SOPSCreationRule `yaml:"creation_rules"`
}

type SOPSCreationRule struct {
	PathRegex string `yaml:"path_regex"`
	Age       string `yaml:"age,omitempty"`
}

func NewSOPSConfig(agePublicKey string) *SOPSConfig {
	return &SOPSConfig{
		CreationRules: []SOPSCreationRule{
			{
				PathRegex: "*.enc.yaml",
				Age:       agePublicKey,
			},
		},
	}
}

func (c *SOPSConfig) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal SOPS config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write SOPS config: %w", err)
	}

	return nil
}

func LoadSOPSConfig(path string) (*SOPSConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SOPS config: %w", err)
	}

	var cfg SOPSConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse SOPS config: %w", err)
	}

	return &cfg, nil
}
