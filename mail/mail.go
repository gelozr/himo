// Package mail sends email through named mailers, with SMTP built in.
package mail

import (
	"context"
	"fmt"
	"sync"
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
	MailDriver        string
	MailHost          string
	MailPort          int
	MailUser          string
	MailPass          string
	MailSkipTLSVerify bool
}

// Manager routes messages to named mailers. It is safe for concurrent use.
type Manager struct {
	mu            sync.RWMutex
	mailers       map[Driver]Mailer
	defaultDriver Driver
}

var _ Mailer = (*Manager)(nil)

// NewManager creates a Manager with the SMTP mailer registered. The default
// driver is cfg.MailDriver, or SMTP when empty.
func NewManager(cfg Config) *Manager {
	defaultDriver := SMTP
	if cfg.MailDriver != "" {
		defaultDriver = Driver(cfg.MailDriver)
	}

	return &Manager{
		mailers:       map[Driver]Mailer{SMTP: NewSMTPMailer(cfg)},
		defaultDriver: defaultDriver,
	}
}

// Mailer returns the mailer registered under driver.
func (m *Manager) Mailer(driver Driver) (Mailer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if ml, ok := m.mailers[driver]; ok {
		return ml, nil
	}
	return nil, fmt.Errorf("mailer %q not found", driver)
}

// Send sends the message with the default driver's mailer.
func (m *Manager) Send(ctx context.Context, msg *Message) error {
	m.mu.RLock()
	driver := m.defaultDriver
	m.mu.RUnlock()

	mailer, err := m.Mailer(driver)
	if err != nil {
		return err
	}

	return mailer.Send(ctx, msg)
}

// RegisterDriver adds a mailer under a new driver name.
func (m *Manager) RegisterDriver(driver Driver, mailer Mailer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.mailers[driver]; ok {
		return fmt.Errorf("driver %q already exists", driver)
	}

	m.mailers[driver] = mailer
	return nil
}

// SetDefaultDriver makes Send use the mailer registered under driver.
func (m *Manager) SetDefaultDriver(driver Driver) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.mailers[driver]; !ok {
		return fmt.Errorf("driver %q not found", driver)
	}

	m.defaultDriver = driver
	return nil
}
