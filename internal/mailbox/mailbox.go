// Package mailbox preserves SMTP mailbox syntax when parsing addresses.
package mailbox

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

var quotedLocal = regexp.MustCompile(`"(?:[^"\\]|\\.)*"@`)
var ipv6Literal = regexp.MustCompile(`(?i)@\[IPv6:[^\[\]]+\]`)

// Valid reports whether address is a bare mailbox, without header syntax outside it.
func Valid(address string) bool {
	if strings.HasPrefix(address, `"`) {
		span := quotedLocal.FindStringIndex(address)
		if span == nil || span[0] != 0 {
			return false
		}
		local := address[1 : span[1]-2]
		if !utf8.ValidString(local) {
			return false
		}
		for i := 0; i < len(local); i++ {
			if local[i] == '\\' {
				i++
				if local[i] > '~' {
					return false
				}
			}
			if local[i] < ' ' || local[i] == '\x7f' {
				return false
			}
		}
		// Go's parser unquotes the local part and rejects an empty one.
		address = "x@" + address[span[1]:]
	}
	// Go's parser accepts IP literals without the SMTP IPv6 tag.
	if local, domain, ok := strings.Cut(address, "@["); ok {
		if tag, ip, ok := strings.Cut(domain, ":"); ok && strings.EqualFold(tag, "IPv6") {
			if !strings.Contains(ip, ":") {
				return false
			}
			address = local + "@[" + ip
		}
	}
	parsed, err := mail.ParseAddress(address)
	return err == nil && parsed.Address == address
}

// ParseAddress preserves SMTP mailbox syntax when parsing an optional display name.
func ParseAddress(value string) (*mail.Address, error) {
	parsed, err := parseAddress(value)
	if err == nil {
		return parsed, nil
	}
	for _, span := range ipv6Literal.FindAllStringIndex(value, -1) {
		start, end := span[0], span[1]
		literal := value[start:end]
		untagged := "@[" + literal[len("@[IPv6:"):]
		candidate, parseErr := parseAddress(value[:start] + untagged + value[end:])
		if parseErr != nil || !strings.HasSuffix(candidate.Address, untagged) {
			continue
		}
		candidate.Address = strings.TrimSuffix(candidate.Address, untagged) + literal
		if Valid(candidate.Address) {
			return candidate, nil
		}
	}
	return nil, err
}

func parseAddress(value string) (*mail.Address, error) {
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
