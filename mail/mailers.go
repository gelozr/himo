package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gelozr/himo/internal/mailbox"
	"github.com/google/uuid"
)

// SMTPMailer sends mail through an SMTP server.
type SMTPMailer struct {
	Host          string
	Port          int
	Username      string
	Password      string
	SkipTLSVerify bool
}

// NewSMTPMailer creates an SMTPMailer from the Mail* fields of cfg.
func NewSMTPMailer(cfg Config) *SMTPMailer {
	return &SMTPMailer{
		Host:          cfg.MailHost,
		Port:          cfg.MailPort,
		Username:      cfg.MailUser,
		Password:      cfg.MailPass,
		SkipTLSVerify: cfg.MailSkipTLSVerify,
	}
}

// Send delivers the message. Cancelling ctx aborts the SMTP exchange.
// Port 465 uses implicit TLS; other ports upgrade with STARTTLS when the server offers it.
// STARTTLS is opportunistic, as in net/smtp.SendMail: without it, mail goes out unencrypted,
// but credentials are never sent (smtp.PlainAuth refuses plaintext except to localhost).
// Authentication is skipped when Username is empty.
func (s *SMTPMailer) Send(ctx context.Context, m *Message) error {
	msg, err := buildMessage(m, time.Now())
	if err != nil {
		return err
	}
	if s.Host == "" {
		return errors.New("SMTP host is required")
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Closing the connection unblocks whatever SMTP command is in flight when ctx ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err = s.deliver(conn, m, msg); err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func (s *SMTPMailer) deliver(conn net.Conn, m *Message, msg []byte) error {
	tlsCfg := &tls.Config{
		ServerName:         s.Host,
		InsecureSkipVerify: s.SkipTLSVerify, //nolint:gosec // opt-in through Config.MailSkipTLSVerify, for local test servers
	}

	if s.Port == 465 {
		conn = tls.Client(conn, tlsCfg)
	}

	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if s.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("start tls: %w", err)
			}
		}
	}

	if s.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("client auth: %w", err)
		}
	}
	if err := checkSMTPUTF8(client, m); err != nil {
		return err
	}
	if err := client.Mail(m.From.Address); err != nil {
		return fmt.Errorf("client mail: %w", err)
	}
	for _, a := range m.To {
		if err := client.Rcpt(a.Address); err != nil {
			return fmt.Errorf("client rcpt: %s: %w", a.Address, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("client data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("writer close: %w", err)
	}

	// The server has accepted the message at this point; a failed QUIT doesn't un-send it.
	_ = client.Quit()
	return nil
}

func checkSMTPUTF8(client *smtp.Client, m *Message) error {
	if ok, _ := client.Extension("SMTPUTF8"); ok {
		return nil
	}
	nonASCII := func(a Address) bool {
		return strings.ContainsFunc(a.Address, func(r rune) bool { return r > unicode.MaxASCII })
	}
	if nonASCII(m.From) || slices.ContainsFunc(m.To, nonASCII) {
		return errors.New("SMTP server does not advertise SMTPUTF8 required by an envelope address")
	}
	return nil
}

const maxHeaderLineLength = 998

// buildMessage renders m as a MIME multipart/alternative message.
func buildMessage(m *Message, now time.Time) ([]byte, error) {
	if err := validateMessage(m); err != nil {
		return nil, err
	}

	body, boundary, err := buildBody(m)
	if err != nil {
		return nil, err
	}

	to := make([]string, len(m.To))
	for i, a := range m.To {
		to[i] = formatAddress(a)
	}
	domain := addressDomain(m.From.Address)

	var (
		message bytes.Buffer
		tooLong string
	)
	writeHeader := func(k, v string) {
		line := k + ": " + v
		if k == "Subject" {
			if encoded := mime.QEncoding.Encode("utf-8", v); encoded != v {
				line = k + ": " + fold(encoded)
			} else if len(line) > maxHeaderLineLength {
				line = foldSubject(line)
			}
		}
		for l := range strings.SplitSeq(line, "\r\n") {
			if len(l) > maxHeaderLineLength && tooLong == "" {
				tooLong = k
			}
		}
		message.WriteString(line + "\r\n")
	}
	writeHeader("MIME-Version", "1.0")
	writeHeader("Date", now.Format(time.RFC1123Z))
	writeHeader("Message-ID", fmt.Sprintf("<%d.%s@%s>", now.UnixNano(), uuid.NewString(), domain))
	writeHeader("Subject", m.Subject)
	writeHeader("From", formatAddress(m.From))
	writeHeader("To", strings.Join(to, ",\r\n "))
	for _, k := range slices.Sorted(maps.Keys(m.Headers)) {
		encoded := mime.QEncoding.Encode("utf-8", m.Headers[k])
		writeHeader(textproto.CanonicalMIMEHeaderKey(k), fold(encoded))
	}
	writeHeader("Content-Type", "multipart/alternative; boundary="+boundary)
	if tooLong != "" {
		return nil, fmt.Errorf("header %s is longer than 998 characters", tooLong)
	}
	message.WriteString("\r\n")
	message.Write(body)

	return message.Bytes(), nil
}

// validateMessage rejects messages that can't be sent, and addresses or
// header values that could inject extra headers.
func validateMessage(m *Message) error {
	if m == nil {
		return errors.New("message is nil")
	}
	if err := checkAddress(m.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	if len(m.To) == 0 {
		return errors.New("no recipients")
	}
	for _, a := range m.To {
		if err := checkAddress(a); err != nil {
			return fmt.Errorf("to: %w", err)
		}
	}
	if hasNewline(m.Subject) {
		return errors.New("subject contains a newline")
	}
	if m.Text == "" && m.HTML == "" {
		return errors.New("empty body")
	}
	for k, v := range m.Headers {
		if !isFieldName(k) || hasNewline(v) {
			return fmt.Errorf("invalid header %q", k)
		}
		if reservedHeaders[textproto.CanonicalMIMEHeaderKey(k)] {
			return fmt.Errorf("header %q is reserved by the mailer", k)
		}
	}
	return nil
}

// buildBody writes the text and HTML parts, quoted-printable encoded, and returns the multipart boundary.
func buildBody(m *Message) ([]byte, string, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range []struct{ typ, content string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		if p.content == "" {
			continue
		}
		part, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {p.typ + `; charset="UTF-8"`},
			"Content-Transfer-Encoding": {"quoted-printable"},
			"Content-Disposition":       {"inline"},
		})
		if err != nil {
			return nil, "", err
		}
		qp := quotedprintable.NewWriter(part)
		if _, err := qp.Write([]byte(p.content)); err != nil {
			return nil, "", err
		}
		if err := qp.Close(); err != nil {
			return nil, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}

	return body.Bytes(), mw.Boundary(), nil
}

// These headers can conflict with the generated message or its SMTP recipients.
// Cc and Bcc are included because the mailer only delivers to To, so those addresses would never get the mail.
var reservedHeaders = map[string]bool{
	"Mime-Version": true, "Date": true, "Message-Id": true, "Subject": true,
	"From": true, "To": true, "Content-Type": true, "Cc": true, "Bcc": true,
	"Content-Transfer-Encoding": true, // The multipart body uses the default 7bit encoding.
}

// SMTPUTF8 can carry Unicode domain labels, so this checks only ASCII syntax.
var invalidSMTPDomainLabel = regexp.MustCompile(`^-|-$|[^a-zA-Z0-9\x{80}-\x{10FFFF}-]`)

func checkAddress(a Address) error {
	if hasNewline(a.Name) || hasNewline(a.Address) {
		return fmt.Errorf("address %q contains a newline", a.Address)
	}
	if !mailbox.Valid(a.Address) {
		return fmt.Errorf("invalid address %q", a.Address)
	}
	domain := addressDomain(a.Address)
	if strings.HasPrefix(domain, "[") {
		tag, _, hasColon := strings.Cut(domain, ":")
		if hasColon && !strings.EqualFold(tag, "[IPv6") {
			return fmt.Errorf("invalid address %q: IPv6 literal requires an IPv6: tag", a.Address)
		}
		return nil
	}
	for label := range strings.SplitSeq(domain, ".") {
		if invalidSMTPDomainLabel.MatchString(label) {
			return fmt.Errorf("invalid address %q: invalid SMTP domain label %q", a.Address, label)
		}
	}
	return nil
}

func addressDomain(address string) string {
	return address[strings.LastIndex(address, "@")+1:]
}

func formatAddress(a Address) string {
	// Let net/mail format the display name without re-quoting the validated mailbox.
	const placeholder = "x@example.com"
	name := strings.TrimSuffix((&mail.Address{Name: a.Name, Address: placeholder}).String(), "<"+placeholder+">")
	if strings.HasPrefix(name, "=?") {
		name = fold(name)
	}
	return name + "<" + a.Address + ">"
}

// fold breaks a header value onto continuation lines between encoded words.
func fold(v string) string {
	return strings.ReplaceAll(v, " =?", "\r\n =?")
}

func foldSubject(line string) string {
	var folded strings.Builder
	// Subject whitespace can be folded before text, but its trailing spaces cannot.
	content := strings.TrimRight(line, " \t")
	trailing := line[len(content):]
	for len(content)+len(trailing) > maxHeaderLineLength {
		cut := strings.LastIndexAny(content[:min(len(content), maxHeaderLineLength+1)], " \t")
		cut = len(strings.TrimRight(content[:cut+1], " \t"))
		if cut == 0 {
			break
		}
		folded.WriteString(content[:cut])
		folded.WriteString("\r\n")
		content = content[cut:]
	}
	return folded.String() + content + trailing
}

// isFieldName reports whether k is a valid header name: printable ASCII except ':' (RFC 5322 section 3.6.8).
func isFieldName(k string) bool {
	if k == "" {
		return false
	}
	for i := range len(k) {
		if k[i] < 33 || k[i] > 126 || k[i] == ':' {
			return false
		}
	}
	return true
}

func hasNewline(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}
