# CPA Plugin PII Filter

English | [Español](README.es.md)

A native privacy filter plugin for CLIProxyAPI v8. It intercepts model requests, detects sensitive text, and redacts it
before the request is forwarded to an upstream provider.

## About this fork

This is a fork of [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter) v0.3.0,
maintained by helixnebulatech. Changes in v0.4.0:

- **New plugin ID `pii-filter`** (was `privacyfilter`). The library is now `pii-filter.so` / `.dylib` / `.dll` and the
  config block is `plugins.configs.pii-filter`. Migrating: delete the old `privacyfilter` library and rename its config
  block, otherwise both plugins load and redact twice.

- **CLIProxyAPI v8.** Built against the plugin SDK `github.com/router-for-me/CLIProxyAPI/v8` v8.0.49 (was v7 with
  schema 1). The plugin registers with the schema version the host announces, capped at schema 10.
- **In-place body edits.** On schema 8+ hosts the plugin returns `body_edits` that replace only the redacted JSON
  strings. Key order, large numbers, and whitespace reach the upstream unchanged (v0.3.0 re-serialized the whole body,
  which reordered keys and rounded integers above 2^53). Bodies with duplicate keys are normalized first so PII cannot
  hide in a shadowed key.
- **Spanish and English PII.** Upstream only covered Chinese phone and ID formats. Added DNI/NIE, Spanish, US, and
  international phones, US SSN, IBAN, grouped card numbers, IPv6, dates of birth, passport and social security numbers,
  and Spanish/English password phrasing (`contraseña es X`, `password is X`, `PIN: [SECRET]
- **Detection fixes.** Weak but explicitly labelled passwords (`password: [SECRET] are now redacted. Emails are no
  longer skipped just because "ssh" appears earlier on the line. Gitleaks rules without `secretGroup` keep the key name
  (`password: [SECRET] instead of `[SECRET]`).
- **Rules path.** Upstream looked for `rules/gitleaks.toml` and relative paths next to the library, but CLIProxyAPI v8
  loads plugins from a temporary shadow copy, so they were never found. `gitleaks_toml` now accepts absolute, `~/`,
  or working-directory-relative paths; empty means the embedded rules.
- **Self-contained.** The detection engine is vendored into `internal/filter` (MIT, from
  [packyme/privacy-filter](https://github.com/packyme/privacy-filter) via
  [rheodev/privacy-filter](https://github.com/rheodev/privacy-filter)).

## What It Does

When CLIProxyAPI receives a request, this plugin scans supported text fields before the request leaves the local
process. If sensitive content is found, the request body is rewritten with redacted placeholders.

Typical use cases:

- Prevent accidental leakage of API keys and tokens
- Remove personal contact information before sending prompts to models
- Apply Gitleaks-style secret detection to LLM traffic
- Keep filtering local to the CLIProxyAPI plugin pipeline

## Features

- Request interceptor for the CLIProxyAPI plugin runtime
- Redacts emails, phone numbers, national IDs, IBANs, cards, IPs, dates of birth, passwords, secrets, private keys, and
  similar sensitive data in English, Spanish, and Chinese (see [Detected data](#detected-data))
- Uses built-in Gitleaks rules from `rules/gitleaks.toml`
- Supports custom Gitleaks rule files
- Handles OpenAI Chat / Completions, OpenAI Responses, Claude, Gemini, and Gemini CLI request bodies
- Can skip filtering by model name or source format
- Builds as a native shared library for Linux, macOS, and Windows

## Requirements

- Go 1.26.10+
- CLIProxyAPI v8 (schema 8+ for in-place body edits; older hosts get a full rewritten body)
- CGO enabled
- `make`

## Build

Clone and build the plugin:

```bash
git clone https://github.com/helixnebulatech/cpa-plugin-pii-filter.git
cd cpa-plugin-pii-filter

make build
```

The default build writes the shared library to the repository root:

- Linux: `pii-filter.so`
- macOS: `pii-filter.dylib`
- Windows: `pii-filter.dll`

Build for a specific platform:

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

Use `BUILD_DIR` to place build output elsewhere:

```bash
BUILD_DIR=dist make build
```

## Use with CLIProxyAPI

Place the shared library in your CLIProxyAPI plugin directory. The gitleaks
rules are embedded in the binary, so no extra files are required:

```text
pii-filter/
└── pii-filter.so        # or pii-filter.dylib / pii-filter.dll
```

Then enable the `pii-filter` plugin in CLIProxyAPI.

Plugin metadata:

- Name: `pii-filter`
- Capability: `RequestInterceptor`
- Author: `helixnebulatech`

## Configuration

The plugin is configured inside CLIProxyAPI's main config file (`config.yaml`).
Under `plugins.configs.<id>`, the host-owned fields (`enabled`, `priority`) are
consumed by CLIProxyAPI, and the remaining YAML subtree is passed to the plugin
verbatim.

Enable the plugin:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    pii-filter:
      enabled: true
```

Enable with custom rules:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    pii-filter:
      enabled: true
      gitleaks_toml: ""        # Empty uses the embedded rules
      skip_models:
        - gpt-4
      skip_formats:
        - openai
```

Plugin fields:

| Field           | Type   | Default | Description                                                                            |
|-----------------|--------|---------|----------------------------------------------------------------------------------------|
| `gitleaks_toml` | string | `""`    | Custom gitleaks rule file: absolute, `~/…`, or relative to the CLIProxyAPI working directory. |
| `skip_models`   | array  | `[]`    | Models that should skip redaction.                                                     |
| `skip_formats`  | array  | `[]`    | Source formats that should skip redaction.                                             |
| `replacement`   | string | unset   | One label for every type, e.g. `"[REDACTED]"`.                                         |
| `replacement_labels` | map | `{}` | Per-type labels keyed by type ID (`email`, `phone`, `id`, `iban`, `bank_card`, `ip`, `dob`, `secret`); they win over `replacement`. |

When `gitleaks_toml` is empty the plugin uses the rules embedded in the binary at build time.

### Invalid configuration

- At startup (`plugin.register`), an invalid config makes registration fail. CLIProxyAPI logs the reason and the
  plugin is not enabled, so check `GET /v0/management/plugins` for `effective_enabled: true`.
- On a hot reload (`plugin.reconfigure`), an invalid config is rejected and the plugin **keeps redacting with the
  previous valid config**, so a typo cannot silently turn filtering off. The host log shows an error such as
  `privacy filter rejected new config, still using the previous valid config: ...` naming the bad field. Fix the
  config and save again to apply it.

### Logging

Plugin logs go through the host's `host.log` callback, so they follow CLIProxyAPI's log level, format, and output and
carry the request ID. Each interception pass that redacts something produces one line listing the JSON paths of the redacted fields, for
example `privacy filter redacted 2 field(s): messages[0].content, system`. Request text is never logged.

## How It Works

The plugin registers a `request_interceptor` with the schema version the host announces in `plugin.register`
(capped at the SDK's schema 10). On schema 8+ hosts it answers with `body_edits`: byte-range replacements of the
redacted JSON string literals only, so key order, number formatting and whitespace reach the upstream exactly as the
client sent them. Bodies with duplicate object keys are normalized first (last key wins) and returned whole, so a
duplicate cannot smuggle text past the filter. Older hosts receive the full rewritten body.

The plugin redacts in both the before-auth and after-auth request interception hooks. Both see the client-format
body (before executor translation). The after-auth pass catches text that other plugins add later in the chain, for
example a lower-priority before-auth interceptor or a higher-priority after-auth interceptor. Redaction is
idempotent, so text that is already clean produces no new hits.

1. Checks `skip_models` and `skip_formats`.
2. Parses the request body as JSON.
3. Redacts every supported prompt field (see the table below).
4. Edits free-form text only.
5. Replaces detected sensitive data with placeholders.
6. Leaves the request unchanged if parsing fails or no supported field is found.

Redacted fields by client format:

| Format                  | Fields                                                                                             |
|-------------------------|----------------------------------------------------------------------------------------------------|
| OpenAI Chat             | `messages[].content` (string or `text` parts)                                                      |
| OpenAI image / video    | `prompt` (string or list of strings) of image and video generation requests                        |
| OpenAI Responses        | `instructions`, `input` (string), `input[].content`, `function_call_output` `output`               |
| Claude                  | `system`, `messages[].content` text blocks, `tool_result` content                                  |
| Gemini                  | `systemInstruction` / `system_instruction` and `contents[].parts[].text`                           |
| Gemini CLI              | The same Gemini fields inside the top-level `request` object                                       |

Left untouched on purpose: tool call arguments (`function_call.arguments`, Claude `tool_use.input`, Gemini
`functionCall` / `functionResponse`), images, files, Claude `thinking` blocks, and Gemini parts marked
`thought: true` (their text is bound to a `thoughtSignature`, so editing it would make the upstream reject the request).

OpenAI Completions requests are covered through `messages`: the host converts them to chat completions before
interceptors run.

Common `skip_formats` values are the host's source format names, such as `openai`, `openai-response`, `claude`,
`gemini`, `gemini-cli`, `openai-image`, and `openai-video`.

Supported request shapes include:

```json
{
  "model": "gpt-4",
  "messages": [
    {
      "role": "user",
      "content": "Email me at user@example.com"
    }
  ]
}
```

```json
{
  "model": "gpt-4",
  "input": "My GitHub token is ghp_xxx"
}
```

## Detected data

| Type ID     | Label         | What is matched                                                                                        |
|-------------|---------------|--------------------------------------------------------------------------------------------------------|
| `email`     | `[EMAIL]`     | Email addresses (not `ssh user@host` targets or `git@host:path` remotes)                               |
| `phone`     | `[PHONE]`     | Spanish (`+34 612 345 678`, `91 234 56 78`), US/Canada (`(415) 555-2671`), any `+CC …` number, China   |
| `id`        | `[ID]`        | Spanish DNI/NIE (control letter checked), US SSN (`123-45-6789`), passport and social security numbers next to a keyword, Chinese ID |
| `iban`      | `[IBAN]`      | IBANs with or without spaces (country length and mod-97 checked)                                       |
| `bank_card` | `[BANK_CARD]` | Card numbers, compact or grouped with spaces/dashes (Luhn checked)                                     |
| `ip`        | `[IP]`        | IPv4 and IPv6                                                                                          |
| `dob`       | `[DOB]`       | Dates after "fecha de nacimiento", "nacido el", "date of birth", "DOB", "born on"                      |
| `secret`    | `[SECRET]`    | Gitleaks rules, high-entropy tokens, and values after `password`/`contraseña`/`clave`/`PIN`/`token`… (`: X`, `= X`, `is X`, `es X`) |

Not detected: names, postal addresses, free-form health or financial data, obfuscated emails (`a [at] b`), and text inside
images or files. This is a regex filter, not an NER model.

## Rules

Built-in rules are embedded into the shared library at build time from:

```text
rules/gitleaks.toml
```

At runtime the plugin uses `gitleaks_toml` when it is set, and the embedded rules otherwise. A `rules/` folder next
to the library is not read: CLIProxyAPI v8 loads plugins from a temporary shadow copy, so the plugin cannot see its
install directory.

Update embedded rules and rebuild:

```bash
make update-rules
make build
```

You can also set `gitleaks_toml` to use your own rule file:

```yaml
gitleaks_toml: ~/.cli-proxy-api/gitleaks.toml
```

Relative paths are resolved from the CLIProxyAPI working directory, so prefer absolute or `~/` paths.

## Development

Common commands:

```bash
go test ./...
make build
make clean
```

Main files:

```text
main.go                 Plugin metadata and build entry
abi.go                  CLIProxyAPI plugin ABI adapter
interceptor.go          Request interception and redaction logic
jsonspan.go             JSON parser that keeps string byte offsets for body edits
config.go               YAML configuration parsing
rules/gitleaks.toml     Built-in detection rules
```

`internal/filter` holds the detection engine (`pii.go`, `pii_intl.go` for Spanish/English, `secrets.go`).

## Credits

- Original plugin: [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- Core filtering logic: [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
