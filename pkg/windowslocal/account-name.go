package windowslocal

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidSAMName checks the existing lexical rules for a bare local SAM account
// name. It neither resolves the name nor proves that an account is local/existing.
func ValidSAMName(name string) bool { return validName(name) }

func validName(name string) bool {
	if name == "" || name == "." || name == ".." || name != strings.TrimSpace(name) || !utf8.ValidString(name) ||
		strings.ContainsAny(name, `\/@"[]:;|=,+*?<>`) || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
