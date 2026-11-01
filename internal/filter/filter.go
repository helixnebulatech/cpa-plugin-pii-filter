// Package filter 在文本进入 LLM 前过滤掉 PII 与密钥。
//
// 纯正则、无模型、O(n)。Filter 编译一次后可并发安全地重复使用。
// 既可被网关直接 import 调用 filter.Redact，也可由 cmd/ 下的 HTTP/gRPC 服务包装。
package filter

import (
	"fmt"
	"sort"
	"strings"
)

// Entity 是一个被脱敏的命中项。Type 是稳定的开放类型 ID，Start/End 为 UTF-8 字节偏移。
type Entity struct {
	Type  string `json:"type"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}

// Result 是一次脱敏的结果。
type Result struct {
	Redacted string   `json:"redacted"`
	Hit      bool     `json:"hit"`
	Count    int      `json:"count"`
	Entities []Entity `json:"entities"`
}

// Config 配置替换文本。按类型指定的标签优先于全局标签，最后使用默认标签。
// Replacement 为空表示使用默认标签；ReplacementLabels 接受任意非空类型 ID。
type Config struct {
	Replacement       string
	ReplacementLabels map[string]string
}

// span 是各检测层内部产出的区间。
type span struct {
	start, end   int
	entityType   string
	defaultLabel string
}

// Filter 持有编译好的规则。创建后只读，可并发安全地复用。
type Filter struct {
	secrets           *secretDetector
	replacement       string
	replacementLabels map[string]string
}

// New 创建一个 Filter。gitleaksTOML 为 gitleaks 规则文件路径；
// 传空字符串则只用内置兜底规则。规则或替换配置无效时返回 error。
func New(gitleaksTOML string, cfg Config) (*Filter, error) {
	if cfg.Replacement != "" && strings.TrimSpace(cfg.Replacement) == "" {
		return nil, fmt.Errorf("replacement must not be whitespace-only")
	}
	var labels map[string]string
	if len(cfg.ReplacementLabels) != 0 {
		labels = make(map[string]string, len(cfg.ReplacementLabels))
		for entityType, label := range cfg.ReplacementLabels {
			if entityType == "" || strings.TrimSpace(entityType) != entityType {
				return nil, fmt.Errorf("replacement_labels key %q must be nonempty without edge whitespace", entityType)
			}
			if strings.TrimSpace(label) == "" {
				return nil, fmt.Errorf("replacement_labels[%q] must be nonempty and not whitespace-only", entityType)
			}
			labels[entityType] = label
		}
	}
	sd, err := newSecretDetector(gitleaksTOML)
	if err != nil {
		return nil, err
	}
	return &Filter{secrets: sd, replacement: cfg.Replacement, replacementLabels: labels}, nil
}

// Stats 返回已加载的规则数，以及因语法不兼容被跳过的规则数。
func (f *Filter) Stats() (rules, skipped int) {
	return len(f.secrets.rules), f.secrets.skipped
}

// Redact 检测并脱敏文本。并发安全。
func (f *Filter) Redact(text string) Result {
	var spans []span
	spans = append(spans, detectPII(text)...)        // 结构化 PII
	spans = append(spans, f.secrets.detect(text)...) // 密钥 / 凭证

	merged := mergeSpans(spans)
	return f.render(text, merged)
}

// render 单遍重建文本与实体；merged 已按起点升序且互不重叠。
func (f *Filter) render(text string, merged []span) Result {
	if len(merged) == 0 {
		return Result{Redacted: text, Entities: []Entity{}}
	}
	var b strings.Builder
	entities := make([]Entity, len(merged))
	prev := 0
	for i, s := range merged {
		label := s.defaultLabel
		if f.replacement != "" {
			label = f.replacement
		}
		if f.replacementLabels != nil {
			if custom, ok := f.replacementLabels[s.entityType]; ok {
				label = custom
			}
		}
		b.WriteString(text[prev:s.start])
		b.WriteString(label)
		entities[i] = Entity{Type: s.entityType, Start: s.start, End: s.end, Text: text[s.start:s.end]}
		prev = s.end
	}
	b.WriteString(text[prev:])
	return Result{
		Redacted: b.String(),
		Hit:      true,
		Count:    len(merged),
		Entities: entities,
	}
}

// mergeSpans 丢弃无效与重叠区间：按起点升序、同起点取更长者，
// 贪心保留互不重叠的区间。原地压缩调用方的内部切片，避免复制候选区间。
func mergeSpans(spans []span) []span {
	valid := spans[:0]
	for _, s := range spans {
		if s.start >= 0 && s.start < s.end {
			valid = append(valid, s)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].start != valid[j].start {
			return valid[i].start < valid[j].start
		}
		return valid[i].end > valid[j].end
	})
	merged := valid[:0]
	lastEnd := -1
	for _, s := range valid {
		if s.start >= lastEnd {
			merged = append(merged, s)
			lastEnd = s.end
		}
	}
	return merged
}
