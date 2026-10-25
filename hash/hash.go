// Package hash hashes and verifies passwords with bcrypt or argon2id.
package hash

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

// ErrHasherNotFound is returned when no Hasher is registered for a Method.
var (
	ErrHasherNotFound = errors.New("hasher not found")
)

// Method names a hashing algorithm.
type Method string

// Built-in Methods.
const (
	Bcrypt   Method = "bcrypt"
	Argon2ID Method = "argon2id"
)

// Hasher performs one-way password hashing and verification.
type Hasher interface {
	Hash(password string) (string, error)
	Check(password, hash string) (bool, error)
}

// Manager is a thread-safe registry of hashers with a default Method.
type Manager struct {
	mu            sync.RWMutex
	hashers       map[Method]Hasher
	defaultHasher Method
}

// New returns a Manager pre-configured with Bcrypt and Argon2ID hashers.
func New() *Manager {
	m := &Manager{
		hashers:       make(map[Method]Hasher),
		defaultHasher: Bcrypt,
	}

	m.hashers[Bcrypt] = BcryptHasher{}
	m.hashers[Argon2ID] = Argon2IDHasher{}

	return m
}

// Hash generates a password hash using the default Method.
func (m *Manager) Hash(password string) (string, error) {
	return m.MustHasher(m.defaultMethod()).Hash(password)
}

// Check verifies a password against a hash. Bcrypt and argon2id hashes are
// recognised by their prefix, so changing the default Method doesn't break
// hashes that are already stored. Any other hash is checked with the default Method.
func (m *Manager) Check(password, hash string) (bool, error) {
	return m.MustHasher(m.methodFor(hash)).Check(password, hash)
}

func (m *Manager) methodFor(hash string) Method {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		return Argon2ID
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return Bcrypt
	}
	return m.defaultMethod()
}

func (m *Manager) defaultMethod() Method {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultHasher
}

// Hasher looks up a Hasher by Method. Returns ErrHasherNotFound if missing.
func (m *Manager) Hasher(mt Method) (Hasher, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hasher, ok := m.hashers[mt]; ok {
		return hasher, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrHasherNotFound, mt)
}

// MustHasher returns a Hasher for the Method or panics if not registered.
func (m *Manager) MustHasher(mt Method) Hasher {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hasher, ok := m.hashers[mt]; ok {
		return hasher
	}

	panic(fmt.Sprintf("hasher '%s' not found", mt))
}

// Extend registers a new Hasher under the given Method, overwriting if existing.
func (m *Manager) Extend(mt Method, hasher Hasher) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.hashers[mt] = hasher
	return nil
}

// SetDefault changes the default Method used by Hash and Check.
// Returns ErrHasherNotFound if the Method is not registered.
func (m *Manager) SetDefault(mt Method) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.hashers[mt]; !ok {
		return fmt.Errorf("%w: %s", ErrHasherNotFound, mt)
	}

	m.defaultHasher = mt
	return nil
}

var (
	once          sync.Once
	defaultHasher *Manager
)

// getManager initializes and returns a package-level singleton Manager.
func getManager() *Manager {
	once.Do(func() {
		defaultHasher = New()
	})
	return defaultHasher
}

// Hash is a facade that hashes using the default Method.
func Hash(password string) (string, error) {
	return getManager().Hash(password)
}

// Check is a facade that verifies a hash, choosing the Method from the hash prefix (see Manager.Check).
func Check(password, hash string) (bool, error) {
	return getManager().Check(password, hash)
}

// LookupHasher looks up a Hasher by Method in the package-level Manager.
func LookupHasher(mt Method) (Hasher, error) {
	return getManager().Hasher(mt)
}

// MustHasher returns a Hasher for the Method or panics if not found.
func MustHasher(mt Method) Hasher {
	return getManager().MustHasher(mt)
}

// Extend registers a new Hasher under the given Method at the package level.
func Extend(mt Method, h Hasher) error {
	return getManager().Extend(mt, h)
}

// SetDefault sets the default Method used by package-level Hash and Check.
func SetDefault(mt Method) error {
	return getManager().SetDefault(mt)
}

// BcryptHasher implements Hasher using the bcrypt algorithm.
type BcryptHasher struct{}

var _ Hasher = BcryptHasher{}

// Hash returns the bcrypt hash of the password using DefaultCost.
func (BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %v", err)
	}
	return string(bytes), nil
}

// Check compares a plaintext password against a bcrypt hash.
func (BcryptHasher) Check(password, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, fmt.Errorf("bcrypt compare password hash: %w", err)
		}
	}

	return true, nil
}

// Argon2IDHasher implements Hasher using the argon2id algorithm.
type Argon2IDHasher struct{}

var _ Hasher = Argon2IDHasher{}

// Hash returns the argon2id hash of the password using DefaultParams.
func (Argon2IDHasher) Hash(password string) (string, error) {
	s, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", fmt.Errorf("argon hash: %w", err)
	}
	return s, nil
}

// Check compares a plaintext password against an argon2id hash.
func (Argon2IDHasher) Check(password, hash string) (bool, error) {
	ok, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, fmt.Errorf("argon compare password hash: %w", err)
	}
	return ok, nil
}
