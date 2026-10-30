package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/gelozr/himo/hash"
)

// Errors returned by MemoryUserProvider.
var (
	ErrUserNotFound      error = &kindError{"user not found", ErrInvalidCredentials}
	ErrUserAlreadyExists       = errors.New("user already exists")
	ErrIncorrectPassword error = &kindError{"incorrect password", ErrInvalidCredentials}
)

// User represents a basic user record for MemoryUserProvider.
// Password holds the plain password on registration and the hash once stored.
type User struct {
	ID       string
	Email    string
	Password string
}

// PasswordCredentials is a simple email/password credential struct.
type PasswordCredentials struct {
	Email    string
	Password string
}

var dummyHash = sync.OnceValue(func() string {
	h, _ := hash.Hash("dummy password")
	return h
})

// MemoryUserProvider is an in-memory, demo/test only UserProvider.
// It stores users keyed by lowercased email and implements FindByCredentials
// to satisfy AnyHandler’s dynamic handler model.
type MemoryUserProvider struct {
	mu    sync.RWMutex
	users map[string]*User
}

var _ UserProvider[any, any] = (*MemoryUserProvider)(nil)
var _ UserRegisterer[any] = (*MemoryUserProvider)(nil)

// NewMemoryUserProvider creates an empty in-memory provider.
// Intended for testing or demos; not for production use.
func NewMemoryUserProvider() *MemoryUserProvider {
	return &MemoryUserProvider{
		users: make(map[string]*User),
	}
}

// FindByCredentials looks up a user by email/password.
// Expects credentials of type PasswordCredentials, returns any to fit AnyHandler.
func (p *MemoryUserProvider) FindByCredentials(_ context.Context, credentials any) (any, error) {
	creds, ok := credentials.(PasswordCredentials)
	if !ok {
		return nil, errors.New("invalid credentials type")
	}

	u, err := p.GetByEmail(creds.Email)
	if err != nil {
		// Spend the same hashing time as a real check so response time doesn't reveal which emails exist.
		_, _ = hash.Check(creds.Password, dummyHash())
		return nil, fmt.Errorf("get user by email: %w", err)
	}

	ok, err = hash.Check(creds.Password, u.Password)
	if err != nil {
		return nil, fmt.Errorf("check password: %w", err)
	}
	if !ok {
		return nil, ErrIncorrectPassword
	}

	return u, nil
}

// GetByEmail returns a copy of the user with the given email or ErrUserNotFound.
func (p *MemoryUserProvider) GetByEmail(email string) (*User, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if u, ok := p.users[strings.ToLower(email)]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, ErrUserNotFound
}

// RegisterUser stores a copy of the user with a generated ID and hashed password.
// Expects user of type *User and returns the stored copy; the argument is not modified.
func (p *MemoryUserProvider) RegisterUser(_ context.Context, user any) (any, error) {
	u, ok := user.(*User)
	if !ok {
		return nil, errors.New("invalid user type")
	}

	hashed, err := hash.Hash(u.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	stored := User{ID: uniqid(), Email: u.Email, Password: hashed}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := strings.ToLower(u.Email)
	if _, ok = p.users[key]; ok {
		return nil, ErrUserAlreadyExists
	}

	p.users[key] = &stored
	cp := stored
	return &cp, nil
}
