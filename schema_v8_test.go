package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestNegotiatedSchemaVersion(t *testing.T) {
	cases := map[uint32]uint32{
		0:                           1,
		1:                           1,
		7:                           7,
		pluginabi.SchemaVersion:     pluginabi.SchemaVersion,
		pluginabi.SchemaVersion + 5: pluginabi.SchemaVersion,
	}
	for host, want := range cases {
		if got := negotiatedSchemaVersion(host); got != want {
			t.Errorf("negotiatedSchemaVersion(%d) = %d, want %d", host, got, want)
		}
	}
}

func TestRegisterEnablesBodyEditsOnlyOnSchema8Hosts(t *testing.T) {
	privacyFilterABIState.Lock()
	previous := privacyFilterABIState.plugin
	privacyFilterABIState.Unlock()
	t.Cleanup(func() {
		privacyFilterABIState.Lock()
		privacyFilterABIState.plugin = previous
		privacyFilterABIState.Unlock()
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"schema test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host      uint32
		wantEdits bool
	}{
		{0, false},
		{pluginabi.SchemaVersionRequestInterceptorBodyPatch - 1, false},
		{pluginabi.SchemaVersionRequestInterceptorBodyPatch, true},
		{pluginabi.SchemaVersion, true},
	} {
		raw, err := json.Marshal(abiLifecycleRequest{ConfigYAML: []byte("gitleaks_toml: rules.toml"), SchemaVersion: tc.host, PluginDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		out, err := handlePrivacyFilterRegister(context.Background(), pluginabi.MethodPluginRegister, raw)
		if err != nil {
			t.Fatalf("host schema %d: register error = %v", tc.host, err)
		}
		if got, want := decodeRegistration(t, out).SchemaVersion, negotiatedSchemaVersion(tc.host); got != want {
			t.Fatalf("host schema %d: registered schema %d, want %d", tc.host, got, want)
		}
		privacyFilterABIState.RLock()
		p := privacyFilterABIState.plugin
		privacyFilterABIState.RUnlock()
		if p.bodyEdits != tc.wantEdits {
			t.Fatalf("host schema %d: bodyEdits = %v, want %v", tc.host, p.bodyEdits, tc.wantEdits)
		}

		body := `{"input":"mail test@example.com"}`
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if tc.wantEdits && (resp.Body != nil || len(resp.BodyEdits) != 1) {
			t.Fatalf("host schema %d: want body edits only, got body=%s edits=%v", tc.host, resp.Body, resp.BodyEdits)
		}
		if !tc.wantEdits && (resp.Body == nil || len(resp.BodyEdits) != 0) {
			t.Fatalf("host schema %d: want full body only, got body=%s edits=%v", tc.host, resp.Body, resp.BodyEdits)
		}
	}
}

func TestBodyEditsPreserveUntouchedBytes(t *testing.T) {
	p := newTestPlugin(t)
	p.bodyEdits = true
	body := "{\n  \"seed\": 12345678901234567890,\n  \"model\":\"gpt-5\",\n  \"messages\": [ {\"role\":\"user\", \"content\":\"<b>hi</b> test@example.com \\u00e9\"} ],\n  \"temperature\": 0.10\n}"
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := applyBodyEdits([]byte(body), resp.BodyEdits)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"seed\": 12345678901234567890,\n  \"model\":\"gpt-5\",\n  \"messages\": [ {\"role\":\"user\", \"content\":\"<b>hi</b> [EMAIL] é\"} ],\n  \"temperature\": 0.10\n}"
	if string(got) != want {
		t.Fatalf("patched body =\n%s\nwant\n%s", got, want)
	}
}

func TestEscapedTextIsRedacted(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"messages":[{"role":"user","content":"test\u0040example.com"}]}`
	got, _, err := redactedBody(p, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || strings.Contains(string(got), "example.com") {
		t.Fatalf("escaped email leaked: %s", got)
	}
}

func TestDuplicateKeysAreNormalized(t *testing.T) {
	p := newTestPlugin(t)
	p.bodyEdits = true
	for _, body := range []string{
		// First duplicate holds the PII: some upstream parsers keep the first key.
		`{"messages":[{"role":"user","content":"test@example.com","content":"hi"}]}`,
		// Duplicates without PII still collapse so nothing hides behind them later.
		`{"model":"a","model":"b","input":"hello"}`,
	} {
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Body == nil || len(resp.BodyEdits) != 0 {
			t.Fatalf("duplicate keys must return a normalized body, got body=%s edits=%v", resp.Body, resp.BodyEdits)
		}
		if strings.Contains(string(resp.Body), "test@example.com") || strings.Count(string(resp.Body), `"content"`) > 1 || strings.Count(string(resp.Body), `"model"`) > 1 {
			t.Fatalf("normalized body still has duplicates or PII: %s", resp.Body)
		}
	}
}
