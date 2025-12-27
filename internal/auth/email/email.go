package email

import (
	"strings"
	"unicode"
)

// IsValidEmail performs lightweight validation of an email address format.
func IsValidEmail(email string) bool {
	if email == "" {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	if !strings.Contains(parts[1], ".") {
		return false
	}
	return true
}

// DeriveNameFromEmail heuristically derives first/last names from an email.
func DeriveNameFromEmail(email string) (string, string) {
	localPart := email
	if at := strings.IndexByte(email, '@'); at > 0 {
		localPart = email[:at]
	}

	parts := strings.FieldsFunc(localPart, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '+'
	})

	if len(parts) == 0 {
		return "User", "User"
	}

	first := capitalize(parts[0])
	last := "User"
	if len(parts) > 1 {
		last = capitalize(parts[len(parts)-1])
	}

	return first, last
}

func capitalize(s string) string {
	if s == "" {
		return s
	}

	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
