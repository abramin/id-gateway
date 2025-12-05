package string

import (
	"strings"
	"unicode"
)

func TrimStrings(ss ...*string) {
	for _, s := range ss {
		*s = strings.TrimSpace(*s)
	}
}

func TrimSlice(ss []string) {
	for i := range ss {
		ss[i] = strings.TrimSpace(ss[i])
	}
}

func ToSnakeCase(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 &&
			(unicode.IsLower(runes[i-1]) || (i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
