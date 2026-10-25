package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Errors returned by session drivers.
var (
	ErrInvalidSessionID = errors.New("invalid session id")
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionExpired   = errors.New("session expired")
	ErrInvalidUser      = errors.New("invalid user")
)

// SessionDriver defines the contract for session-based drivers.
// U is the user type; P is the proof type used by Validate (often string).
// Login must return a session ID (string), and Logout removes that session.
type SessionDriver[U, P any] interface {
	Validator[U, P] // Validate(ctx, proof P) -> Verified[U]
	Login(ctx context.Context, user U) (string, error)
	Logout(ctx context.Context, sessionID string) error
}

const sessionTTL = time.Hour

// session holds in-memory session data.
type session struct {
	uid string
	exp time.Time
}

// MemorySessionDriver is an in-memory implementation of SessionDriver.
// Useful for testing or simple setups without external storage.
type MemorySessionDriver struct {
	mu        sync.Mutex
	sessions  map[string]session
	lastSweep time.Time
}

var _ SessionDriver[any, any] = (*MemorySessionDriver)(nil)

// NewMemorySessionDriver initializes a MemorySessionDriver with an empty session store.
func NewMemorySessionDriver() *MemorySessionDriver {
	return &MemorySessionDriver{
		sessions: make(map[string]session),
	}
}

// Validate checks that the session ID exists and is unexpired,
// and returns a Verified user context.
func (m *MemorySessionDriver) Validate(_ context.Context, proof any) (Verified[any], error) {
	sessionID, ok := proof.(string)
	if !ok {
		return Verified[any]{}, ErrInvalidSessionID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[sessionID]
	if !ok {
		return Verified[any]{}, ErrSessionNotFound
	}

	if time.Now().After(sess.exp) {
		delete(m.sessions, sessionID)
		return Verified[any]{}, ErrSessionExpired
	}

	return Verified[any]{
		User: &User{ID: sess.uid},
	}, nil
}

// Login generates a new session ID for the given user and stores it in memory.
func (m *MemorySessionDriver) Login(_ context.Context, user any) (string, error) {
	usr, ok := user.(*User)
	if !ok || usr.ID == "" {
		return "", ErrInvalidUser
	}

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if now.Sub(m.lastSweep) > sweepInterval {
		for id, s := range m.sessions {
			if now.After(s.exp) {
				delete(m.sessions, id)
			}
		}
		m.lastSweep = now
	}

	sessID := uniqid()
	m.sessions[sessID] = session{uid: usr.ID, exp: now.Add(sessionTTL)}

	return sessID, nil
}

// Logout removes the session with the given ID from the in-memory store.
func (m *MemorySessionDriver) Logout(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[sessionID]; !ok {
		return ErrSessionNotFound
	}

	delete(m.sessions, sessionID)

	return nil
}
