package filter

import (
	"math/big"
	"net"
	"regexp"
	"strings"
)

// Spanish and English PII. Checksummed identifiers (DNI/NIE, IBAN, SSN, cards)
// are validated after matching so random numbers are not redacted; the rest
// rely on separators or a nearby keyword.
var (
	reDNI = regexp.MustCompile(`[0-9]{8}(?:-?[A-Za-z]|[ ][A-Z])`)
	reNIE = regexp.MustCompile(`[XYZxyz][\s-]?[0-9]{7}[\s-]?[A-Za-z]`)
	// Spanish numbers: optional +34/0034, then 9 digits starting with 6-9 with
	// optional single space or dash separators (612 345 678, 612 34 56 78,
	// 912-345-678). Dots are left out so dotted quads are not read as phones.
	rePhoneES = regexp.MustCompile(`(?:(?:\+|00)34[\s.-]?)?[6789](?:[\s-]?[0-9]){8}`)
	// NANP (US/CA): (415) 555-2671, 415-555-2671, +1 415 555 2671.
	rePhoneNANP = regexp.MustCompile(`(?:\+?1[\s.-]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[\s.-]?[2-9][0-9]{2}[\s.-]?[0-9]{4}`)
	// Generic E.164 with a leading "+": +44 20 7946 0958, +33 6 12 34 56 78.
	rePhoneIntl = regexp.MustCompile(`\+[1-9][0-9]{0,3}(?:[\s.-]?\(?[0-9]{1,4}\)?){2,6}`)
	reSSN       = regexp.MustCompile(`[0-9]{3}-[0-9]{2}-[0-9]{4}`)
	reIBAN      = regexp.MustCompile(`[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){10,30}`)
	// Card numbers written in groups: 4111 1111 1111 1111, 4111-1111-1111-1111.
	reCardGrouped = regexp.MustCompile(`[0-9]{4}(?:[ -][0-9]{3,6}){2,4}`)
	reIPv6        = regexp.MustCompile(`[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*`)

	// Keyword-anchored values. Only the value group (1) is redacted.
	reDOB = regexp.MustCompile(`(?i)(?:fecha\s+de\s+nacimiento|f\.\s*nacimiento|nacid[oa]\s+el|date\s+of\s+birth|birth\s*date|\bdob\b|born\s+on)\s*[:=]?\s*` +
		`([0-9]{1,4}[/.-][0-9]{1,2}[/.-][0-9]{1,4})`)
	rePassport       = regexp.MustCompile(`(?i)(?:pasaporte|passport)(?:\s*(?:n[º°o.]?|no\.?|num\.?|número|numero|number|#))?\s*[:=]?\s*([A-Z]{1,3}[0-9]{6,9}|[0-9]{8,9})\b`)
	reSocialSecurity = regexp.MustCompile(`(?i)(?:\bssn\b|\bnss\b|n[º°]?\s*(?:de\s+)?(?:la\s+)?seguridad\s+social|seguridad\s+social|social\s+security(?:\s+number)?)\s*[:=#]?\s*` +
		`([0-9][0-9 /-]{7,14}[0-9])`)
)

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// ibanLengths holds the total IBAN length per country (SWIFT IBAN registry),
// so a match is cut at the right place and trailing words are not swallowed.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
	"BH": 22, "BR": 29, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18,
	"DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22,
	"GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22,
	"IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LI": 21,
	"LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27,
	"MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
	"TN": 24, "TR": 26, "UA": 29, "VG": 24, "XK": 20,
}

func isAlnum(b byte) bool {
	return isDigit(b) || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// alnumBounded rejects matches glued to letters or digits on either side.
func alnumBounded(text string, start, end int) bool {
	if start > 0 && isAlnum(text[start-1]) {
		return false
	}
	if end < len(text) && isAlnum(text[end]) {
		return false
	}
	return true
}

func digitsOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func compactAlnum(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isAlnum(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return strings.ToUpper(b.String())
}

// dniValid checks the control letter of a Spanish DNI or NIE.
func dniValid(s string) bool {
	c := compactAlnum(s)
	if len(c) != 9 {
		return false
	}
	switch c[0] {
	case 'X':
		c = "0" + c[1:]
	case 'Y':
		c = "1" + c[1:]
	case 'Z':
		c = "2" + c[1:]
	}
	n := 0
	for i := 0; i < 8; i++ {
		if !isDigit(c[i]) {
			return false
		}
		n = n*10 + int(c[i]-'0')
	}
	return dniLetters[n%23] == c[8]
}

func ibanValid(compact string) bool {
	rearranged := compact[4:] + compact[:4]
	var digits strings.Builder
	for i := 0; i < len(rearranged); i++ {
		ch := rearranged[i]
		switch {
		case isDigit(ch):
			digits.WriteByte(ch)
		case ch >= 'A' && ch <= 'Z':
			v := int(ch-'A') + 10
			digits.WriteByte(byte('0' + v/10))
			digits.WriteByte(byte('0' + v%10))
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(digits.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

// ibanSpan trims a raw IBAN match to the registered length of its country and
// returns the end offset, or -1 when it is not a valid IBAN.
func ibanSpan(text string, start, end int) int {
	want, ok := ibanLengths[text[start:start+2]]
	if !ok {
		return -1
	}
	count := 0
	for i := start; i < end; i++ {
		if !isAlnum(text[i]) {
			continue
		}
		count++
		if count == want {
			if !ibanValid(compactAlnum(text[start : i+1])) {
				return -1
			}
			return i + 1
		}
	}
	return -1
}

func ssnValid(s string) bool {
	area, group, serial := s[0:3], s[4:6], s[7:11]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	return group != "00" && serial != "0000"
}

// trimTrailingSeparators drops separators a lazy phone match may end on.
func trimTrailingSeparators(text string, start, end int) int {
	for end > start && !isDigit(text[end-1]) {
		end--
	}
	return end
}

func detectIntlPII(text string) []span {
	var spans []span
	add := func(start, end int, entityType, label string) {
		spans = append(spans, span{start, end, entityType, label})
	}

	for _, re := range []*regexp.Regexp{reDNI, reNIE} {
		for _, m := range re.FindAllStringIndex(text, -1) {
			if alnumBounded(text, m[0], m[1]) && dniValid(text[m[0]:m[1]]) {
				add(m[0], m[1], "id", "[ID]")
			}
		}
	}
	for _, m := range reSSN.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) && ssnValid(text[m[0]:m[1]]) {
			add(m[0], m[1], "id", "[ID]")
		}
	}
	for _, m := range reIBAN.FindAllStringIndex(text, -1) {
		if m[0] > 0 && isAlnum(text[m[0]-1]) {
			continue
		}
		if end := ibanSpan(text, m[0], m[1]); end > 0 && (end == len(text) || !isAlnum(text[end])) {
			add(m[0], end, "iban", "[IBAN]")
		}
	}
	for _, m := range reCardGrouped.FindAllStringIndex(text, -1) {
		digits := digitsOf(text[m[0]:m[1]])
		if digitBounded(text, m[0], m[1]) && len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
			add(m[0], m[1], "bank_card", "[BANK_CARD]")
		}
	}

	for _, m := range rePhoneES.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) {
			add(m[0], m[1], "phone", "[PHONE]")
		}
	}
	for _, m := range rePhoneNANP.FindAllStringIndex(text, -1) {
		raw := text[m[0]:m[1]]
		// Bare 10-digit runs are usually IDs or timestamps; require formatting.
		if digitBounded(text, m[0], m[1]) && (strings.ContainsAny(raw, " .-()") || raw[0] == '+') {
			add(m[0], m[1], "phone", "[PHONE]")
		}
	}
	for _, m := range rePhoneIntl.FindAllStringIndex(text, -1) {
		end := trimTrailingSeparators(text, m[0], m[1])
		if n := len(digitsOf(text[m[0]:end])); n >= 8 && n <= 15 && digitBounded(text, m[0], end) {
			add(m[0], end, "phone", "[PHONE]")
		}
	}

	for _, m := range reIPv6.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		for e > s && (text[e-1] == '.' || text[e-1] == ':') && !strings.HasSuffix(text[s:e], "::") {
			e--
		}
		if s > 0 && isAlnum(text[s-1]) || e < len(text) && isAlnum(text[e]) {
			continue
		}
		cand := text[s:e]
		if len(cand) < 6 || strings.Trim(cand, ":") == "" {
			continue
		}
		if ip := net.ParseIP(cand); ip != nil && ip.To4() == nil {
			add(s, e, "ip", "[IP]")
		}
	}

	for _, rule := range []struct {
		re         *regexp.Regexp
		entityType string
		label      string
	}{
		{reDOB, "dob", "[DOB]"},
		{rePassport, "id", "[ID]"},
		{reSocialSecurity, "id", "[ID]"},
	} {
		for _, m := range rule.re.FindAllStringSubmatchIndex(text, -1) {
			if m[2] >= 0 {
				add(m[2], m[3], rule.entityType, rule.label)
			}
		}
	}
	return spans
}
