package main

import _ "embed"

// embeddedGitleaks holds the built-in gitleaks rules compiled into the shared
// library. The store installer only ships the dynamic library, so we embed the
// rules so the plugin works without extra files.
//
//go:embed rules/gitleaks.toml
var embeddedGitleaks []byte
