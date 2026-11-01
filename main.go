package main

import (
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

var pluginVersion = "0.4.0"

// buildPlugin parses the config and compiles the filter. pluginDir is only
// set by hosts that send plugin_dir; it anchors relative gitleaks_toml paths.
func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}

	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
	}

	f, errFilter := newFilter(pluginDir, cfg)
	if errFilter != nil {
		return pluginapi.Plugin{}, errFilter
	}
	p.filter = f

	return pluginapi.Plugin{
		Metadata: pluginMetadata(),
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor: p,
		},
	}, nil
}

func pluginMetadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:             pluginName,
		Version:          pluginVersion,
		Author:           "helixnebulatech",
		GitHubRepository: "https://github.com/helixnebulatech/cpa-plugin-pii-filter",
		ConfigFields: []pluginapi.ConfigField{
			{
				Name:        "gitleaks_toml",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Path to a gitleaks.toml rules file (absolute, ~/..., or relative to the CLIProxyAPI working directory). Empty uses the embedded rules.",
			},
			{
				Name:        "replacement",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Global redaction label. Unset uses built-in labels; per-type labels take precedence.",
			},
			{
				Name:        "replacement_labels",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Redaction labels keyed by entity type ID (email, secret, phone, id, iban, bank_card, ip, dob, or future types).",
			},
			{
				Name:        "skip_models",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Model names to skip redaction for.",
			},
			{
				Name:        "skip_formats",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Source format names to skip redaction for.",
			},
		},
	}
}
