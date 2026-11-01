package filter

import (
	"strings"
	"testing"
)

func TestSpanishAndEnglishPII(t *testing.T) {
	f := newFilter(t)
	cases := []struct {
		name  string
		input string
		leak  string // must not survive redaction
		label string
	}{
		{"dni", "Mi DNI es 12345678Z", "12345678Z", "[ID]"},
		{"dni dash", "DNI: 12345678-Z", "12345678-Z", "[ID]"},
		{"nie", "NIE X1234567L", "X1234567L", "[ID]"},
		{"phone es", "Teléfono: +34 612 345 678", "612 345 678", "[PHONE]"},
		{"phone es compact", "llámame al 612345678", "612345678", "[PHONE]"},
		{"phone es pairs", "fijo 91 234 56 78", "234 56 78", "[PHONE]"},
		{"phone es 0034", "0034612345678", "612345678", "[PHONE]"},
		{"phone us parens", "Call (415) 555-2671 today", "555-2671", "[PHONE]"},
		{"phone us dashes", "cell: 415-555-2671", "555-2671", "[PHONE]"},
		{"phone us +1", "+1 415 555 2671", "555 2671", "[PHONE]"},
		{"phone uk", "ring +44 20 7946 0958", "7946 0958", "[PHONE]"},
		{"phone fr", "+33 6 12 34 56 78", "12 34 56 78", "[PHONE]"},
		{"ssn", "SSN 123-45-6789", "123-45-6789", "[ID]"},
		{"iban es spaced", "IBAN: ES91 2100 0418 4502 0005 1332 EUR", "2100 0418", "[IBAN]"},
		{"iban es compact", "ES9121000418450200051332", "21000418450200051332", "[IBAN]"},
		{"iban de", "DE89 3704 0044 0532 0130 00", "3704 0044", "[IBAN]"},
		{"card spaced", "Tarjeta 4111 1111 1111 1111", "4111 1111", "[BANK_CARD]"},
		{"card dashed", "card 4111-1111-1111-1111", "4111-1111", "[BANK_CARD]"},
		{"ipv6", "server 2001:db8::8a2e:370:7334 down", "2001:db8::8a2e", "[IP]"},
		{"dob es", "Fecha de nacimiento: 14/03/1985", "14/03/1985", "[DOB]"},
		{"dob en", "DOB: 1985-03-14", "1985-03-14", "[DOB]"},
		{"passport es", "Pasaporte nº PAA123456", "PAA123456", "[ID]"},
		{"passport en", "passport number: 123456789", "123456789", "[ID]"},
		{"nss", "Nº de la Seguridad Social: 28 1234567890", "1234567890", "[ID]"},
		{"password es", "mi contraseña es Hunter2Segura", "Hunter2Segura", "[SECRET]"},
		{"clave", "la clave: gatito99", "gatito99", "[SECRET]"},
		{"password is", "my password is hunter2", "hunter2", "[SECRET]"},
		{"weak password", "password: Summer2024", "Summer2024", "[SECRET]"},
		{"pin", "PIN: 4821", "4821", "[SECRET]"},
		{"db url", "postgres://admin:S3cr3tP4ss@db.example.com/prod password=S3cr3tP4ss", "password=S3cr3tP4ss", "[SECRET]"},
		{"email after ssh prose", "Usa ssh, y luego escríbeme a juan@gmail.com", "juan@gmail.com", "[EMAIL]"},
		{"email with colon", "creds juan@gmail.com:hunter2", "juan@gmail.com", "[EMAIL]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := f.Redact(tc.input).Redacted
			if strings.Contains(got, tc.leak) || !strings.Contains(got, tc.label) {
				t.Fatalf("input %q -> %q, want %q removed and %s present", tc.input, got, tc.leak, tc.label)
			}
		})
	}
}

func TestSpanishAndEnglishFalsePositives(t *testing.T) {
	f := newFilter(t)
	for _, input := range []string{
		"DNI de ejemplo 12345678A",            // wrong control letter
		"pedido 12345678 y factura",           // 8 digits, no letter
		"timestamp 1700000000 ms",             // bare 10 digits
		"order id 4155552671",                 // bare 10 digits are not a US phone
		"ES00 1234 5678 9012 3456 7890",       // IBAN checksum fails
		"versión 1.2.3 del 12:30:45",          // times and versions are not IPv6
		"use std::vector and a::b",            // C++ scopes
		"card 1234 5678 9012 3456",            // Luhn fails
		"password: required",                  // form documentation
		"la contraseña es incorrecta",         // prose about a password
		"ssh -p 22 deploy@server.example.com", // ssh target
		"git@github.com:org/repo.git",         // scp-style git remote
		"SSN format is 000-12-3456",           // invalid SSN area
		"999.999.999.999",                     // not an IP or a phone
	} {
		if r := f.Redact(input); r.Hit {
			t.Errorf("unexpected redaction: %q -> %q", input, r.Redacted)
		}
	}
}

func TestGitleaksRuleKeepsKeyLabel(t *testing.T) {
	f := newFilter(t)
	got := f.Redact("password: Summer2024 y tarjeta").Redacted
	if got != "password: [SECRET] y tarjeta" {
		t.Fatalf("got %q", got)
	}
}
