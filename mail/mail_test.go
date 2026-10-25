package mail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func testMessage() *Message {
	return &Message{
		From:    Address{Name: "Sender", Address: "from@example.com"},
		To:      []Address{{Name: "Ünïcode Name", Address: "to@example.com"}},
		Subject: "Hello wörld",
		Text:    "a=b and a long line " + strings.Repeat("x", 100),
		HTML:    "<p>hi</p>",
		Headers: map[string]string{"x-tag": "welcome"},
	}
}

func TestBuildMessage(t *testing.T) {
	raw, err := buildMessage(testMessage(), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("not a valid message: %v", err)
	}

	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if subject != "Hello wörld" {
		t.Errorf("Subject = %q", subject)
	}
	if to, err := msg.Header.AddressList("To"); err != nil || to[0].Name != "Ünïcode Name" {
		t.Errorf("To = %v, %v", to, err)
	}
	if !strings.HasSuffix(msg.Header.Get("Message-ID"), "@example.com>") {
		t.Errorf("Message-ID = %q", msg.Header.Get("Message-ID"))
	}
	if msg.Header.Get("X-Tag") != "welcome" {
		t.Errorf("custom header missing")
	}

	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	part, err := mr.NextPart() // decodes quoted-printable
	if err != nil {
		t.Fatal(err)
	}
	text, _ := io.ReadAll(part)
	if string(text) != testMessage().Text {
		t.Errorf("text body = %q", text)
	}
}

func TestBuildMessage_FoldsLongHeaders(t *testing.T) {
	m := testMessage()
	m.Subject = strings.Repeat("привет ", 30)
	m.To = nil
	for i := range 40 {
		m.To = append(m.To, Address{Address: fmt.Sprintf("recipient%02d@example.com", i)})
	}

	raw, err := buildMessage(m, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for l := range strings.SplitSeq(string(raw), "\r\n") {
		if len(l) > 998 {
			t.Fatalf("line of %d characters", len(l))
		}
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); subject != m.Subject {
		t.Errorf("Subject = %q", subject)
	}
	if to, err := msg.Header.AddressList("To"); err != nil || len(to) != 40 {
		t.Errorf("To: %d addresses, %v", len(to), err)
	}
}

func TestBuildMessage_FoldsLongDisplayNames(t *testing.T) {
	m := testMessage()
	name := strings.TrimSpace(strings.Repeat("привет ", 60))
	m.From.Name, m.To[0].Name = name, name

	raw, err := buildMessage(m, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"From", "To"} {
		if addrs, err := msg.Header.AddressList(h); err != nil || addrs[0].Name != name {
			t.Errorf("%s = %v, %v", h, addrs, err)
		}
	}
}

func TestBuildMessage_RejectsHeaderInjection(t *testing.T) {
	for name, edit := range map[string]func(*Message){
		"subject": func(m *Message) { m.Subject = "hi\r\nBcc: victim@example.com" },
		"to":      func(m *Message) { m.To[0].Address = "to@example.com\r\nBcc: victim@example.com" },
		"name":    func(m *Message) { m.From.Name = "x\nBcc: victim@example.com" },
		"header":  func(m *Message) { m.Headers["X-A"] = "v\r\nBcc: victim@example.com" },
		"no rcpt": func(m *Message) { m.To = nil },
		"no body": func(m *Message) { m.Text, m.HTML = "", "" },
		"dup":     func(m *Message) { m.Headers["content-type"] = "text/plain" },
		"bcc":     func(m *Message) { m.Headers["Bcc"] = "victim@example.com" },
		"empty k": func(m *Message) { m.Headers[""] = "v" },
		"space k": func(m *Message) { m.Headers["X Foo"] = "v" },
		"long":    func(m *Message) { m.Subject = strings.Repeat("a", 1000) },
	} {
		m := testMessage()
		edit(m)
		if _, err := buildMessage(m, time.Now()); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// fakeSMTP serves one connection. If silent, it never replies.
func fakeSMTP(t *testing.T, silent bool) (*SMTPMailer, <-chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if silent {
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 localhost ready")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				_ = tp.PrintfLine("250 localhost")
			case line == "DATA":
				_ = tp.PrintfLine("354 go ahead")
				data, _ := tp.ReadDotBytes()
				got <- string(data)
				_ = tp.PrintfLine("250 ok")
			case line == "QUIT":
				_ = tp.PrintfLine("221 bye")
				return
			default:
				_ = tp.PrintfLine("250 ok")
			}
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return &SMTPMailer{Host: "127.0.0.1", Port: addr.Port}, got
}

func TestSMTPMailer_Send(t *testing.T) {
	m, got := fakeSMTP(t, false)
	if err := m.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	if data := <-got; !strings.Contains(data, "Subject:") {
		t.Errorf("server got %q", data)
	}
}

func TestSMTPMailer_SendHonoursContext(t *testing.T) {
	m, _ := fakeSMTP(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := m.Send(ctx, testMessage()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want context.DeadlineExceeded", err)
	}
}

func TestManager(t *testing.T) {
	m := NewManager(Config{})
	fake := mailerFunc(func(context.Context, *Message) error { return nil })

	if err := m.RegisterDriver("fake", fake); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterDriver("fake", fake); err == nil {
		t.Error("expected duplicate driver error")
	}
	if err := m.SetDefaultDriver("missing"); err == nil {
		t.Error("expected missing driver error")
	}
	if err := m.SetDefaultDriver("fake"); err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), testMessage()); err != nil {
		t.Error(err)
	}
}

type mailerFunc func(context.Context, *Message) error

func (f mailerFunc) Send(ctx context.Context, m *Message) error { return f(ctx, m) }
