package filter

import (
	"regexp"
	"strings"
)

// 结构化 PII 正则。Go 的 regexp 是 RE2，不支持前后向断言，
// 因此数字边界用 digitBounded / ipBounded 在匹配后手工校验。
var (
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePhoneCN  = regexp.MustCompile(`(?:\+?86[-\s]?)?1[3-9][0-9]{9}`)
	reIDCard   = regexp.MustCompile(`[1-9][0-9]{16}[0-9Xx]`)
	reBankCard = regexp.MustCompile(`[0-9]{13,19}`)
	reIPv4     = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`)
)

// 远程命令前缀。user@host 出现在这些命令上下文里通常是 SSH 目标，不是邮箱。
var sshCommands = []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "}

// reSSHArgsBeforeTarget matches the flags that may sit between an ssh-family
// command and its user@host target, e.g. "-p 22 -i ~/.ssh/key ".
var reSSHArgsBeforeTarget = regexp.MustCompile(`^(?:-{1,2}[A-Za-z0-9-]+(?:[ =][^\s@-][^\s@]*)?\s+)*$`)

// isInSSHCommandContext reports whether the email match is the target of an
// ssh/scp/rsync command on the same line ("ssh user@host"), where it is a host
// login rather than an email address. Only flags may sit between the command
// and the match, so prose that merely mentions ssh earlier still gets redacted.
func isInSSHCommandContext(text string, emailStart int) bool {
	lineStart := strings.LastIndexByte(text[:emailStart], '\n') + 1
	line := text[lineStart:emailStart]
	for _, cmd := range sshCommands {
		idx := strings.LastIndex(line, cmd)
		if idx < 0 || (idx > 0 && isAlnum(line[idx-1])) {
			continue
		}
		if reSSHArgsBeforeTarget.MatchString(line[idx+len(cmd):]) {
			return true
		}
	}
	return false
}

// isSCPStyleTarget reports whether the email match is followed by a
// ":path" suffix as in git@github.com:org/repo.git or user@host:~/dir.
func isSCPStyleTarget(text string, end int) bool {
	if end >= len(text) || text[end] != ':' {
		return false
	}
	rest := text[end+1:]
	if i := strings.IndexAny(rest, " \t\r\n\"'`"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ContainsAny(rest, "/@:") || strings.HasPrefix(rest, "~") ||
		strings.HasSuffix(rest, ".git") || rest == "."
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// digitBounded 校验匹配两侧不是数字（替代 RE2 没有的前后向断言）。
func digitBounded(text string, start, end int) bool {
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return true
}

// ipBounded 校验匹配两侧不是数字或点。
func ipBounded(text string, start, end int) bool {
	if start > 0 && (isDigit(text[start-1]) || text[start-1] == '.') {
		return false
	}
	if end < len(text) && (isDigit(text[end]) || text[end] == '.') {
		return false
	}
	return true
}

// luhnValid 做 Luhn 校验，过滤掉「长得像卡号的普通数字串」。
func luhnValid(num string) bool {
	sum := 0
	double := false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// detectPII 返回结构化 PII 的命中区间。
func detectPII(text string) []span {
	var spans []span
	for _, m := range reEmail.FindAllStringIndex(text, -1) {
		// SSH-style URL: user@host:path —— 邮箱后紧接 ":" + 非空白字符 → 视作 git@ URL，不脱
		if isSCPStyleTarget(text, m[1]) {
			continue
		}
		// SSH 命令上下文：ssh / scp / rsync user@host 这种调用，host 不是邮箱
		if isInSSHCommandContext(text, m[0]) {
			continue
		}
		spans = append(spans, span{m[0], m[1], "email", "[EMAIL]"})
	}
	for _, m := range rePhoneCN.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) {
			spans = append(spans, span{m[0], m[1], "phone", "[PHONE]"})
		}
	}
	for _, m := range reIDCard.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) {
			spans = append(spans, span{m[0], m[1], "id", "[ID]"})
		}
	}
	for _, m := range reIPv4.FindAllStringIndex(text, -1) {
		if ipBounded(text, m[0], m[1]) {
			spans = append(spans, span{m[0], m[1], "ip", "[IP]"})
		}
	}
	for _, m := range reBankCard.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) && luhnValid(text[m[0]:m[1]]) {
			spans = append(spans, span{m[0], m[1], "bank_card", "[BANK_CARD]"})
		}
	}
	spans = append(spans, detectIntlPII(text)...)
	return spans
}
