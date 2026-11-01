package filter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestReplacementPrecedence(t *testing.T) {
	text := "邮箱 a@b.com 手机 13812345678"
	for _, tt := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"default", Config{}, "邮箱 [EMAIL] 手机 [PHONE]"},
		{"global", Config{Replacement: "<private>"}, "邮箱 <private> 手机 <private>"},
		{"type_before_default", Config{ReplacementLabels: map[string]string{"email": "<mail>"}}, "邮箱 <mail> 手机 [PHONE]"},
		{"type_before_global", Config{Replacement: "<private>", ReplacementLabels: map[string]string{"email": "<mail>"}}, "邮箱 <mail> 手机 <private>"},
		{"label_spaces_preserved", Config{Replacement: " * ", ReplacementLabels: map[string]string{"email": " 邮件 "}}, "邮箱  邮件  手机  * "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New("", tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			res := f.Redact(text)
			if res.Redacted != tt.want {
				t.Errorf("Redacted = %q, want %q", res.Redacted, tt.want)
			}
			if !res.Hit || res.Count != 2 || len(res.Entities) != 2 {
				t.Fatalf("unexpected result: %+v", res)
			}
			if res.Entities[0].Type != "email" || res.Entities[1].Type != "phone" {
				t.Errorf("types must not depend on labels: %+v", res.Entities)
			}
		})
	}
}

func TestDefaultLabelsAndStableTypes(t *testing.T) {
	f, err := New("", Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ text, entityType, label, original string }{
		{"邮箱 a@b.com", "email", "[EMAIL]", "a@b.com"},
		{"手机 13812345678", "phone", "[PHONE]", "13812345678"},
		{"身份证 11010519900307743X", "id", "[ID]", "11010519900307743X"},
		{"卡号 4111111111111111", "bank_card", "[BANK_CARD]", "4111111111111111"},
		{"地址 192.168.1.2", "ip", "[IP]", "192.168.1.2"},
		{"密码是 Hunter2xy", "secret", "[SECRET]", "Hunter2xy"},
	} {
		t.Run(tt.entityType, func(t *testing.T) {
			res := f.Redact(tt.text)
			if res.Redacted != strings.Replace(tt.text, tt.original, tt.label, 1) {
				t.Errorf("default output changed: %+v", res)
			}
			if res.Count != 1 || len(res.Entities) != 1 {
				t.Fatalf("unexpected entity count: %+v", res)
			}
			entity := res.Entities[0]
			if entity.Type != tt.entityType || entity.Text != tt.original || tt.text[entity.Start:entity.End] != tt.original {
				t.Errorf("unexpected entity: %+v", entity)
			}
		})
	}
}

func TestUTF8EntityOffsets(t *testing.T) {
	f, err := New("", Config{Replacement: "🚫", ReplacementLabels: map[string]string{"email": "邮件"}})
	if err != nil {
		t.Fatal(err)
	}
	text := "你好🙂 a@b.com，然后 13812345678 完毕"
	res := f.Redact(text)
	if res.Redacted != "你好🙂 邮件，然后 🚫 完毕" {
		t.Errorf("unexpected output: %q", res.Redacted)
	}
	want := []Entity{
		{Type: "email", Start: len("你好🙂 "), End: len("你好🙂 a@b.com"), Text: "a@b.com"},
		{Type: "phone", Start: len("你好🙂 a@b.com，然后 "), End: len("你好🙂 a@b.com，然后 13812345678"), Text: "13812345678"},
	}
	if !reflect.DeepEqual(res.Entities, want) {
		t.Errorf("entities = %+v, want %+v", res.Entities, want)
	}
}

func TestReplacementMapSnapshot(t *testing.T) {
	labels := map[string]string{"email": "<original>"}
	f, err := New("", Config{Replacement: "<global>", ReplacementLabels: labels})
	if err != nil {
		t.Fatal(err)
	}
	labels["email"] = "<changed>"
	labels["phone"] = "<new>"
	delete(labels, "email")
	if got := f.Redact("a@b.com 13812345678").Redacted; got != "<original> <global>" {
		t.Errorf("configuration not snapshotted: %q", got)
	}
}

func TestInvalidReplacementConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  Config
	}{
		{"global_spaces", Config{Replacement: " \t\n"}},
		{"global_unicode_spaces", Config{Replacement: "\u2003"}},
		{"empty_key", Config{ReplacementLabels: map[string]string{"": "*"}}},
		{"leading_key_space", Config{ReplacementLabels: map[string]string{" email": "*"}}},
		{"trailing_key_space", Config{ReplacementLabels: map[string]string{"email\u2003": "*"}}},
		{"empty_label", Config{ReplacementLabels: map[string]string{"email": ""}}},
		{"blank_label", Config{ReplacementLabels: map[string]string{"email": "\t\u2003"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New("", tt.cfg)
			if err == nil || f != nil {
				t.Errorf("invalid config accepted: filter=%v error=%v", f, err)
			}
		})
	}
}

func TestNoHitReturnsOriginalAndEmptyJSONArray(t *testing.T) {
	f, err := New("", Config{Replacement: "*"})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"", "你好🙂 hello world"} {
		res := f.Redact(text)
		if res.Redacted != text || res.Hit || res.Count != 0 || res.Entities == nil || len(res.Entities) != 0 {
			t.Errorf("unexpected no-hit result: %+v", res)
		}
		data, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `"entities":[]`) {
			t.Errorf("entities must encode as []: %s", data)
		}
	}
}

func TestArbitraryEntityTypeRendering(t *testing.T) {
	// Exercise the real renderer with internal spans, without adding a detector.
	const entityType = "future/custom kind"
	text := "前缀🙂 sensitive 后缀"
	spans := []span{{start: len("前缀🙂 "), end: len("前缀🙂 sensitive"), entityType: entityType, defaultLabel: "<future-default>"}}
	for _, tt := range []struct {
		name  string
		cfg   Config
		label string
	}{
		{"default", Config{}, "<future-default>"},
		{"global", Config{Replacement: "<global>"}, "<global>"},
		{"map", Config{Replacement: "<global>", ReplacementLabels: map[string]string{entityType: "<specific>", "unused/future": "*"}}, "<specific>"},
		{"unrelated_map", Config{ReplacementLabels: map[string]string{"unused/future": "*"}}, "<future-default>"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New("", tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			res := f.render(text, spans)
			if res.Redacted != "前缀🙂 "+tt.label+" 后缀" || !res.Hit || res.Count != 1 {
				t.Errorf("unexpected render result: %+v", res)
			}
			if len(res.Entities) != 1 || res.Entities[0].Type != entityType || res.Entities[0].Text != "sensitive" {
				t.Errorf("arbitrary type lost: %+v", res.Entities)
			}
		})
	}
}

func TestMergeSpansPreservesOverlapSelection(t *testing.T) {
	spans := []span{
		{start: 6, end: 9, entityType: "later", defaultLabel: "<later>"},
		{start: 0, end: 2, entityType: "short", defaultLabel: "<short>"},
		{start: 0, end: 5, entityType: "first", defaultLabel: "<first>"},
		{start: 0, end: 5, entityType: "tied", defaultLabel: "<tied>"},
		{start: 3, end: 10, entityType: "overlap", defaultLabel: "<overlap>"},
		{start: -1, end: 2, entityType: "invalid"},
		{start: 5, end: 5, entityType: "empty"},
		{start: 9, end: 10, entityType: "adjacent", defaultLabel: "<adjacent>"},
	}
	want := []span{
		{start: 0, end: 5, entityType: "first", defaultLabel: "<first>"},
		{start: 6, end: 9, entityType: "later", defaultLabel: "<later>"},
		{start: 9, end: 10, entityType: "adjacent", defaultLabel: "<adjacent>"},
	}
	if got := mergeSpans(spans); !reflect.DeepEqual(got, want) {
		t.Fatalf("selected spans = %+v, want %+v", got, want)
	}
}
