package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/helixnebulatech/cpa-plugin-pii-filter/internal/filter"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type privacyFilterPlugin struct {
	cfg       privacyFilterConfig
	pluginDir string
	filter    *filter.Filter
	// bodyEdits reports whether the host applies RequestInterceptResponse.BodyEdits
	// (schema 8+). Older hosts ignore them, so the full body is returned instead.
	bodyEdits bool
}

var _ pluginapi.RequestInterceptor = (*privacyFilterPlugin)(nil)

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

// InterceptRequestAfterAuth redacts again because other plugins can add text
// after the before-auth pass: lower-priority before-auth interceptors and
// higher-priority after-auth interceptors both run later in the chain.
// Redaction is idempotent, so already-clean text produces no hits.
func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

func (p *privacyFilterPlugin) interceptRequest(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	resp := pluginapi.RequestInterceptResponse{}

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if len(req.Body) == 0 {
		return resp, nil
	}

	result, err := p.redactPayload(req.Body)
	if err != nil {
		pluginLog(ctx, logLevelWarn, "privacy filter failed to process request body: "+err.Error(), map[string]any{
			"error": err.Error(),
		})
		return resp, nil
	}
	if result.body == nil && len(result.edits) == 0 {
		return resp, nil
	}
	if len(result.hits) > 0 {
		// The host text formatter only prints a fixed set of field names, so the
		// summary is repeated in the message.
		message := fmt.Sprintf("privacy filter redacted %d field(s): %s", len(result.hits), strings.Join(result.hits, ", "))
		pluginLog(ctx, logLevelInfo, message, map[string]any{
			"model":           req.Model,
			"source_format":   req.SourceFormat,
			"redacted_count":  len(result.hits),
			"redacted_fields": result.hits,
		})
	}
	if result.body == nil && !p.bodyEdits {
		if result.body, err = applyBodyEdits(req.Body, result.edits); err != nil {
			pluginLog(ctx, logLevelWarn, "privacy filter failed to apply redactions: "+err.Error(), map[string]any{
				"error": err.Error(),
			})
			return resp, nil
		}
		result.edits = nil
	}
	resp.Body = result.body
	resp.BodyEdits = result.edits
	return resp, nil
}

type redactResult struct {
	// edits are byte-range replacements against the original body. They are
	// used whenever the body can be patched in place, which keeps every other
	// byte (key order, number formatting, whitespace) exactly as the client sent it.
	edits []pluginapi.RequestBodyEdit
	// body replaces the whole request when the original had to be normalized
	// first (duplicate keys or extreme nesting).
	body []byte
	hits []string
}

// redactPayload returns the body changes and the JSON paths of the redacted
// fields. Non-JSON bodies pass through untouched.
func (p *privacyFilterPlugin) redactPayload(body []byte) (redactResult, error) {
	root, err := parseJSONSpans(body)
	if errors.Is(err, errNeedsNormalize) {
		return p.redactNormalized(body)
	}
	if err != nil {
		return redactResult{}, nil
	}
	payload, ok := root.(map[string]any)
	if !ok {
		return redactResult{}, nil
	}
	r := &redaction{filter: p.filter}
	r.payload(payload, "")
	if r.err != nil {
		return redactResult{}, r.err
	}
	return redactResult{edits: r.edits, hits: r.hits}, nil
}

// redactNormalized handles bodies whose duplicate keys could hide text from
// the walker. The normalized body is always returned, even without hits, so
// the upstream never sees a duplicate the walker skipped.
func (p *privacyFilterPlugin) redactNormalized(body []byte) (redactResult, error) {
	normalized, err := normalizeJSON(body)
	if err != nil {
		return redactResult{}, fmt.Errorf("failed to normalize request: %w", err)
	}
	inner, err := p.redactPayload(normalized)
	if err != nil {
		return redactResult{}, err
	}
	if inner.body != nil {
		return redactResult{}, fmt.Errorf("normalized request still needs normalization")
	}
	patched, err := applyBodyEdits(normalized, inner.edits)
	if err != nil {
		return redactResult{}, err
	}
	return redactResult{body: patched, hits: inner.hits}, nil
}

// applyBodyEdits splices edits that are sorted and non-overlapping, as the
// walker produces them.
func applyBodyEdits(body []byte, edits []pluginapi.RequestBodyEdit) ([]byte, error) {
	sorted := append([]pluginapi.RequestBodyEdit(nil), edits...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Start < sorted[j].Start })
	out := make([]byte, 0, len(body))
	prev := 0
	for _, e := range sorted {
		if e.Start < prev || e.End < e.Start || e.End > len(body) {
			return nil, fmt.Errorf("invalid body edit [%d:%d]", e.Start, e.End)
		}
		out = append(out, body[prev:e.Start]...)
		out = append(out, e.Replacement...)
		prev = e.End
	}
	return append(out, body[prev:]...), nil
}

// redaction walks the prompt-bearing fields of the client request formats the
// host passes to interceptors (OpenAI chat, OpenAI Responses, OpenAI image and
// video generation, Claude, Gemini and Gemini CLI). Only free-form text is rewritten; structured data such as tool
// call arguments, function responses, files and images is left untouched.
type redaction struct {
	filter *filter.Filter
	hits   []string
	edits  []pluginapi.RequestBodyEdit
	err    error
}

// stringValue returns the decoded text of a JSON string node.
func stringValue(v any) (string, bool) {
	s, ok := v.(*jsonString)
	if !ok {
		return "", false
	}
	return s.value, true
}

func (r *redaction) payload(m map[string]any, path string) bool {
	changed := false
	// messages: OpenAI chat and Claude. input: OpenAI Responses. contents: Gemini.
	for _, key := range []string{"messages", "input", "contents"} {
		changed = r.itemsField(m, key, path) || changed
	}
	// system: Claude. instructions: OpenAI Responses.
	for _, key := range []string{"system", "instructions"} {
		changed = r.contentField(m, key, path) || changed
	}
	for _, key := range []string{"systemInstruction", "system_instruction"} {
		if instruction, ok := m[key].(map[string]any); ok {
			changed = r.item(instruction, joinPath(path, key)) || changed
		}
	}
	changed = r.promptField(m, path) || changed
	// Gemini CLI wraps a Gemini request in a top-level "request" object.
	if inner, ok := m["request"].(map[string]any); ok && path == "" {
		changed = r.payload(inner, "request") || changed
	}
	return changed
}

func (r *redaction) itemsField(m map[string]any, key, path string) bool {
	path = joinPath(path, key)
	switch v := m[key].(type) {
	case *jsonString:
		return r.stringField(m, key, path)
	case []any:
		changed := false
		for i, item := range v {
			if itemMap, ok := item.(map[string]any); ok {
				changed = r.item(itemMap, fmt.Sprintf("%s[%d]", path, i)) || changed
			}
		}
		return changed
	}
	return false
}

// item handles a single conversation entry: an OpenAI/Claude message, an
// OpenAI Responses input item, or a Gemini content / system instruction.
func (r *redaction) item(m map[string]any, path string) bool {
	changed := r.contentField(m, "content", path)
	if typ, _ := stringValue(m["type"]); typ == "function_call_output" {
		changed = r.contentField(m, "output", path) || changed
	}
	if parts, ok := m["parts"].([]any); ok {
		changed = r.parts(parts, joinPath(path, "parts")) || changed
	}
	return changed
}

func (r *redaction) parts(parts []any, path string) bool {
	changed := false
	for i, part := range parts {
		if partMap, ok := part.(map[string]any); ok {
			changed = r.part(partMap, fmt.Sprintf("%s[%d]", path, i)) || changed
		}
	}
	return changed
}

func (r *redaction) part(m map[string]any, path string) bool {
	// Gemini thought parts are bound to a thoughtSignature; rewriting their
	// text would make the upstream reject the signature.
	if thought, _ := m["thought"].(bool); thought {
		return false
	}
	changed := r.stringField(m, "text", joinPath(path, "text"))
	if typ, _ := stringValue(m["type"]); typ == "tool_result" {
		changed = r.contentField(m, "content", path) || changed
	}
	return changed
}

// contentField redacts a value that is either plain text or a list of parts.
func (r *redaction) contentField(m map[string]any, key, path string) bool {
	path = joinPath(path, key)
	switch v := m[key].(type) {
	case *jsonString:
		return r.stringField(m, key, path)
	case []any:
		return r.parts(v, path)
	}
	return false
}

// promptField handles the image/video generation prompt (a string or a list of
// strings). Completions requests never reach interceptors in this shape: the
// host converts them to chat completions first.
func (r *redaction) promptField(m map[string]any, path string) bool {
	path = joinPath(path, "prompt")
	switch v := m["prompt"].(type) {
	case *jsonString:
		return r.stringField(m, "prompt", path)
	case []any:
		changed := false
		for i, item := range v {
			if text, ok := item.(*jsonString); ok {
				changed = r.text(text, fmt.Sprintf("%s[%d]", path, i)) || changed
			}
		}
		return changed
	}
	return false
}

func (r *redaction) stringField(m map[string]any, key, path string) bool {
	text, ok := m[key].(*jsonString)
	if !ok {
		return false
	}
	return r.text(text, path)
}

// text redacts one string node and records an edit replacing its raw literal.
func (r *redaction) text(node *jsonString, path string) bool {
	result := r.filter.Redact(node.value)
	if !result.Hit {
		return false
	}
	literal, err := encodeJSONString(result.Redacted)
	if err != nil {
		r.err = fmt.Errorf("failed to encode redacted text at %s: %w", path, err)
		return false
	}
	r.hits = append(r.hits, path)
	r.edits = append(r.edits, pluginapi.RequestBodyEdit{Start: node.start, End: node.end, Replacement: literal})
	return true
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
