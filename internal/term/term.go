// Package term makes untrusted text safe to print to a terminal.
package term

import (
	"strings"
	"unicode"
)

// Clean drops control and format characters (escape sequences, bidi
// overrides) from text that came from a bundle or a server before it
// reaches a terminal.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}
