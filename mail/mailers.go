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
	"slices"
	"strconv"
	"strings"
	"time"

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

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Closing the connection unblocks whatever SMTP command is in flight when ctx ends.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := s.deliver(conn, m, msg); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
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
		to[i] = fold((&mail.Address{Name: a.Name, Address: a.Address}).String())
	}
	domain := m.From.Address[strings.LastIndex(m.From.Address, "@")+1:]

	var (
		sb      strings.Builder
		tooLong string
	)
	// Long values are folded (CRLF + space) between addresses and encoded words;
	// a physical line still over the RFC 5322 limit of 998 characters is rejected.
	writeHeader := func(k, v string) {
		line := k + ": " + v
		for l := range strings.SplitSeq(line, "\r\n") {
			if len(l) > 998 && tooLong == "" {
				tooLong = k
			}
		}
		sb.WriteString(line + "\r\n")
	}
	writeHeader("MIME-Version", "1.0")
	writeHeader("Date", now.Format(time.RFC1123Z))
	writeHeader("Message-ID", fmt.Sprintf("<%d.%s@%s>", now.UnixNano(), uuid.NewString(), domain))
	writeHeader("Subject", encode(m.Subject))
	writeHeader("From", fold((&mail.Address{Name: m.From.Name, Address: m.From.Address}).String()))
	writeHeader("To", strings.Join(to, ",\r\n "))
	for _, k := range slices.Sorted(maps.Keys(m.Headers)) {
		writeHeader(textproto.CanonicalMIMEHeaderKey(k), encode(m.Headers[k]))
	}
	writeHeader("Content-Type", "multipart/alternative; boundary="+boundary)
	if tooLong != "" {
		return nil, fmt.Errorf("header %s is longer than 998 characters", tooLong)
	}
	sb.WriteString("\r\n")
	sb.Write(body)

	return []byte(sb.String()), nil
}

// validateMessage rejects messages that can't be sent, and addresses or
// header values that could inject extra headers.
func validateMessage(m *Message) error {
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
			return fmt.Errorf("header %q is set by the mailer", k)
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

// reservedHeaders are written by buildMessage; duplicates would break or contradict the message.
// Bcc is included because it would be shown to every recipient and never delivered.
var reservedHeaders = map[string]bool{
	"Mime-Version": true, "Date": true, "Message-Id": true, "Subject": true,
	"From": true, "To": true, "Content-Type": true, "Bcc": true,
}

func checkAddress(a Address) error {
	if hasNewline(a.Name) || hasNewline(a.Address) {
		return fmt.Errorf("address %q contains a newline", a.Address)
	}
	parsed, err := mail.ParseAddress(a.Address)
	if err != nil || parsed.Address != a.Address {
		return fmt.Errorf("invalid address %q", a.Address)
	}
	return nil
}

// fold breaks a header value onto continuation lines between encoded words.
func fold(v string) string {
	return strings.ReplaceAll(v, " =?", "\r\n =?")
}

func encode(v string) string {
	return fold(mime.QEncoding.Encode("utf-8", v))
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
