package filter

import (
	"strings"
	"testing"
)

func benchmarkRedaction(b *testing.B, replacement string, labels map[string]string, text string) {
	f, err := New("", Config{Replacement: replacement, ReplacementLabels: labels})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for range b.N {
		benchmarkResult = f.Redact(text)
	}
}

var benchmarkResult Result

func BenchmarkRedactConfig(b *testing.B) {
	for _, size := range []struct {
		name    string
		padding string
	}{
		{"short", "hello world "},
		{"long", strings.Repeat("hello world ", 2730)},
	} {
		b.Run("no_hit/default/"+size.name, func(b *testing.B) {
			benchmarkRedaction(b, "", nil, size.padding)
		})
		text := size.padding + "contact a@b.com phone 13812345678"
		b.Run("sparse/default/"+size.name, func(b *testing.B) {
			benchmarkRedaction(b, "", nil, text)
		})
		for _, label := range []struct{ name, value string }{
			{"short_output", "*"},
			{"long_output", strings.Repeat("redacted", 32)},
		} {
			b.Run("sparse/global/"+size.name+"/"+label.name, func(b *testing.B) {
				benchmarkRedaction(b, label.value, nil, text)
			})
			b.Run("sparse/map/"+size.name+"/"+label.name, func(b *testing.B) {
				benchmarkRedaction(b, "", map[string]string{"email": label.value, "phone": label.value}, text)
			})
		}
	}
	text := strings.Repeat("password=alice@example.com 13812345678 4111111111111111 ", 128)
	b.Run("dense_overlapping/default", func(b *testing.B) {
		benchmarkRedaction(b, "", nil, text)
	})
	b.Run("dense_overlapping/global", func(b *testing.B) {
		benchmarkRedaction(b, "*", nil, text)
	})
	b.Run("dense_overlapping/map", func(b *testing.B) {
		benchmarkRedaction(b, "", map[string]string{"secret": "*", "email": "*", "phone": "*", "bank_card": "*"}, text)
	})
}
