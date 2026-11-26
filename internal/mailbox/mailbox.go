// Package mailbox preserves SMTP mailbox syntax when parsing addresses.
package mailbox

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

var quotedLocal = regexp.MustCompile(`"(?:[^"\\]|\\.)*"@`)

// Valid reports whether address is a bare mailbox, without header syntax outside it.
func Valid(address string) bool {
	if strings.HasPrefix(address, `"`) {
		span := quotedLocal.FindStringIndex(address)
		if span == nil || span[0] != 0 {
			return false
		}
		for i := range span[1] {
			if address[i] < ' ' || address[i] > '~' {
				return false
			}
		}
		// Go's parser unquotes the local part and rejects an empty one.
		address = "x@" + address[span[1]:]
	}
	parsed, err := mail.ParseAddress(address)
	return err == nil && parsed.Address == address
}

// ParseAddress keeps the original quoting when parsing a mailbox with an optional name.
func ParseAddress(value string) (*mail.Address, error) {
	parsed, err := mail.ParseAddress(value)
	probe := "quoted-local@"
	if parsed != nil && strings.HasPrefix(parsed.Address, probe) {
		probe = "other-quoted-local@"
	}
	for offset := 0; offset < len(value); {
		span := quotedLocal.FindStringIndex(value[offset:])
		if span == nil {
			break
		}
		start, end := offset+span[0], offset+span[1]
		// A candidate can start at a display name's closing quote and overlap the local part.
		offset = start + 1
		// A quote can be in a name or comment. Only restore it if the probe became the local part.
		withProbe, probeErr := mail.ParseAddress(value[:start] + probe + value[end:])
		if probeErr != nil || !strings.HasPrefix(withProbe.Address, probe) {
			continue
		}
		withProbe.Address = value[start:end] + strings.TrimPrefix(withProbe.Address, probe)
		if !Valid(withProbe.Address) {
			return nil, fmt.Errorf("invalid address %q", withProbe.Address)
		}
		return withProbe, nil
	}
	return parsed, err
}
