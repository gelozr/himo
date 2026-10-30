// Package mail sends email through named mailers, with SMTP built in.
package mail

import (
	"context"
	"errors"
	"fmt"

	"github.com/gelozr/himo/internal/registry"
)

// Driver names a registered Mailer.
type Driver string

// SMTP is the driver name of the built-in SMTPMailer.
const SMTP = Driver("smtp")

// Mailer sends a message.
type Mailer interface {
	Send(context.Context, *Message) error
}

// Address is an email address with an optional display name.
type Address struct {
	Name    string
	Address string
}

// Message is an email with a plain text and/or HTML body.
// Headers adds extra headers; the ones the mailer sets itself (From, To, Subject, ...) are rejected.
type Message struct {
	From    Address
	To      []Address
	Subject string
	HTML    string
	Text    string
	Headers map[string]string
}

// Config configures NewManager and the SMTP mailer.
type Config struct {
	MailHost          string
	MailPort          int
	MailUser          string
	MailPass          string
	MailSkipTLSVerify bool
}

// ErrMailerNotFound is returned when no Mailer is registered for a Driver.
var ErrMailerNotFound = errors.New("mailer not found")

// Manager routes messages to named mailers. It is safe for concurrent use.
type Manager struct {
	mailers *registry.Registry[Driver, Mailer]
}

var _ Mailer = (*Manager)(nil)

// NewManager creates a Manager with the SMTP mailer registered as the default.
// Use RegisterDriver and SetDefaultDriver to send through another Mailer.
func NewManager(cfg Config) *Manager {
	m := &Manager{mailers: registry.New[Driver, Mailer](ErrMailerNotFound)}
	m.mailers.Set(SMTP, NewSMTPMailer(cfg))
	return m
}

// Mailer returns the mailer registered under driver.
func (m *Manager) Mailer(driver Driver) (Mailer, error) {
	return m.mailers.Get(driver)
}

// Send sends the message with the default driver's mailer.
func (m *Manager) Send(ctx context.Context, msg *Message) error {
	return m.mailers.Default().Send(ctx, msg)
}

// RegisterDriver adds a mailer under a new driver name.
func (m *Manager) RegisterDriver(driver Driver, mailer Mailer) error {
	if !m.mailers.Add(driver, mailer) {
		return fmt.Errorf("driver %q already exists", driver)
	}
	return nil
}

// SetDefaultDriver makes Send use the mailer registered under driver.
func (m *Manager) SetDefaultDriver(driver Driver) error {
	return m.mailers.SetDefault(driver)
}
