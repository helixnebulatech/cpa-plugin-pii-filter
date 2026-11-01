package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/helixnebulatech/cpa-plugin-pii-filter/internal/filter"

	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "pii-filter"
const pluginName = "pii-filter"

type privacyFilterConfig struct {
	GitleaksTOML      string            `yaml:"gitleaks_toml"`
	SkipModels        []string          `yaml:"skip_models"`
	SkipFormats       []string          `yaml:"skip_formats"`
	Replacement       string            `yaml:"replacement"`
	ReplacementLabels map[string]string `yaml:"replacement_labels"`
}

// replacementLabel prevents YAML's string decoder from coercing booleans and
// numbers into labels. A null field is left unset by the YAML decoder.
type replacementLabel string

func (label *replacementLabel) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("replacement label must be a string")
	}
	if strings.TrimSpace(node.Value) == "" {
		return fmt.Errorf("replacement label must not be empty or whitespace-only")
	}
	*label = replacementLabel(node.Value)
	return nil
}

type replacementLabels map[string]string

func (labels *replacementLabels) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("replacement_labels must be a mapping")
	}
	if len(node.Content) == 0 {
		return nil
	}
	values := make(map[string]string, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("replacement_labels keys must be strings")
		}
		if key.Value == "" || strings.TrimSpace(key.Value) != key.Value {
			return fmt.Errorf("replacement_labels key %q must be nonempty without edge whitespace", key.Value)
		}
		if _, exists := values[key.Value]; exists {
			return fmt.Errorf("duplicate replacement_labels key %q", key.Value)
		}
		var label replacementLabel
		if err := label.UnmarshalYAML(value); err != nil {
			return fmt.Errorf("replacement_labels[%q]: %w", key.Value, err)
		}
		values[key.Value] = string(label)
	}
	*labels = values
	return nil
}

func (cfg *privacyFilterConfig) UnmarshalYAML(node *yaml.Node) error {
	var values struct {
		GitleaksTOML      string            `yaml:"gitleaks_toml"`
		SkipModels        []string          `yaml:"skip_models"`
		SkipFormats       []string          `yaml:"skip_formats"`
		Replacement       replacementLabel  `yaml:"replacement"`
		ReplacementLabels replacementLabels `yaml:"replacement_labels"`
	}
	if err := node.Decode(&values); err != nil {
		return err
	}
	*cfg = privacyFilterConfig{
		GitleaksTOML:      values.GitleaksTOML,
		SkipModels:        values.SkipModels,
		SkipFormats:       values.SkipFormats,
		Replacement:       string(values.Replacement),
		ReplacementLabels: map[string]string(values.ReplacementLabels),
	}
	return nil
}

func defaultConfig() privacyFilterConfig {
	return privacyFilterConfig{}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid pii-filter config: %w", err)
		}
	}
	return cfg, nil
}

// resolveGitleaksPath resolves the configured gitleaks rule file. An empty
// path means the rules embedded in the binary. "~/" expands to the home
// directory, and other relative paths resolve against baseDir: the plugin
// directory when an older host sends it, otherwise the host's working
// directory. The plugin's own location is never used because CLIProxyAPI v8
// loads plugins from a temporary shadow copy.
func (cfg *privacyFilterConfig) resolveGitleaksPath(baseDir string) (path string, embedded bool, err error) {
	path = strings.TrimSpace(cfg.GitleaksTOML)
	if path == "" {
		return "", true, nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, errHome := os.UserHomeDir()
		if errHome != nil {
			return "", false, fmt.Errorf("resolve gitleaks_toml %q: %w", cfg.GitleaksTOML, errHome)
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~")), false, nil
	}
	if filepath.IsAbs(path) {
		return path, false, nil
	}
	if baseDir != "" {
		return filepath.Join(baseDir, path), false, nil
	}
	abs, errAbs := filepath.Abs(path)
	if errAbs != nil {
		return "", false, fmt.Errorf("resolve gitleaks_toml %q: %w", cfg.GitleaksTOML, errAbs)
	}
	return abs, false, nil
}

func (cfg *privacyFilterConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		trimmed := strings.TrimSpace(m)
		if strings.EqualFold(trimmed, model) || strings.EqualFold(trimmed, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

func newFilter(baseDir string, cfg privacyFilterConfig) (*filter.Filter, error) {
	tomlPath, embedded, errPath := cfg.resolveGitleaksPath(baseDir)
	if errPath != nil {
		return nil, errPath
	}

	// The filter loads its rules from a file path, so the embedded rules are
	// materialized into a temporary file. Compiled rules live in memory, so the temp
	// file is removed right after the filter is constructed.
	if embedded {
		tmp, errTmp := os.CreateTemp("", "pii-filter-gitleaks-*.toml")
		if errTmp != nil {
			return nil, fmt.Errorf("create temp rules file: %w", errTmp)
		}
		tmpPath := tmp.Name()
		if _, errWrite := tmp.Write(embeddedGitleaks); errWrite != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("write temp rules file: %w", errWrite)
		}
		if errClose := tmp.Close(); errClose != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("close temp rules file: %w", errClose)
		}
		defer func() { _ = os.Remove(tmpPath) }()
		tomlPath = tmpPath
	}

	f, err := filter.New(tomlPath, filter.Config{
		Replacement:       cfg.Replacement,
		ReplacementLabels: cfg.ReplacementLabels,
	})
	if err != nil {
		source := "embedded rules"
		if !embedded {
			source = fmt.Sprintf("gitleaks_toml %q", tomlPath)
		}
		return nil, fmt.Errorf("failed to create privacy filter from %s: %w", source, err)
	}
	rules, skipped := f.Stats()
	pluginLog(context.Background(), logLevelInfo, fmt.Sprintf("privacy filter loaded: %d rules, %d skipped", rules, skipped), map[string]any{
		"rules":         rules,
		"skipped_rules": skipped,
	})
	return f, nil
}
