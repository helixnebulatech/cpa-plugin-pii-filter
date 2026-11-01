package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// jsonString is a decoded JSON string together with the byte range of its raw
// literal (quotes included) in the source body, so a redaction can be sent to
// the host as a localized body edit instead of a re-serialized body.
type jsonString struct {
	value      string
	start, end int
}

// maxJSONDepth matches encoding/json's nesting limit.
const maxJSONDepth = 10000

// errNeedsNormalize marks bodies that are valid JSON but cannot be patched in
// place safely: duplicate object keys (parsers disagree on which one wins) or
// nesting deeper than maxJSONDepth.
var errNeedsNormalize = errors.New("json body needs normalization")

// parseJSONSpans decodes a JSON document into map[string]any / []any values,
// with strings as *jsonString, numbers as json.Number, and bools and null as
// usual.
func parseJSONSpans(data []byte) (any, error) {
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid json")
	}
	p := &spanParser{data: data}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, fmt.Errorf("trailing data at offset %d", p.pos)
	}
	return v, nil
}

// spanParser only runs on input that already passed json.Valid, so it checks
// structure loosely and leaves strict validation to the standard library.
type spanParser struct {
	data []byte
	pos  int
}

func (p *spanParser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *spanParser) value(depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errNeedsNormalize
	}
	p.skipSpace()
	if p.pos >= len(p.data) {
		return nil, fmt.Errorf("unexpected end of json")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		p.pos += len("true")
		return true, nil
	case c == 'f':
		p.pos += len("false")
		return false, nil
	case c == 'n':
		p.pos += len("null")
		return nil, nil
	default:
		start := p.pos
		for p.pos < len(p.data) && bytes.IndexByte([]byte("+-.0123456789eE"), p.data[p.pos]) >= 0 {
			p.pos++
		}
		return json.Number(p.data[start:p.pos]), nil
	}
}

func (p *spanParser) object(depth int) (any, error) {
	p.pos++ // '{'
	m := make(map[string]any)
	p.skipSpace()
	if p.data[p.pos] == '}' {
		p.pos++
		return m, nil
	}
	for {
		p.skipSpace()
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := m[key.value]; dup {
			return nil, errNeedsNormalize
		}
		p.skipSpace()
		p.pos++ // ':'
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		m[key.value] = v
		p.skipSpace()
		if p.data[p.pos] == ',' {
			p.pos++
			continue
		}
		p.pos++ // '}'
		return m, nil
	}
}

func (p *spanParser) array(depth int) (any, error) {
	p.pos++ // '['
	items := make([]any, 0)
	p.skipSpace()
	if p.data[p.pos] == ']' {
		p.pos++
		return items, nil
	}
	for {
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
		p.skipSpace()
		if p.data[p.pos] == ',' {
			p.pos++
			continue
		}
		p.pos++ // ']'
		return items, nil
	}
}

func (p *spanParser) str() (*jsonString, error) {
	start := p.pos
	p.pos++ // opening quote
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case '\\':
			p.pos += 2
		case '"':
			p.pos++
			var s string
			if err := json.Unmarshal(p.data[start:p.pos], &s); err != nil {
				return nil, err
			}
			return &jsonString{value: s, start: start, end: p.pos}, nil
		default:
			p.pos++
		}
	}
	return nil, fmt.Errorf("unterminated string at offset %d", start)
}

// encodeJSONString renders s as a JSON string literal without HTML escaping,
// matching what clients usually send.
func encodeJSONString(s string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return string(bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}

// normalizeJSON re-serializes a body through encoding/json so duplicate keys
// collapse to one (last wins) before redaction. Numbers keep their exact text.
func normalizeJSON(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
