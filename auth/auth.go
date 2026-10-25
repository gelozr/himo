// Package auth authenticates users with pluggable user providers and drivers
// (JWT or session), managed as named handlers.
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// Common errors returned by Manager when operations are unsupported
var (
	ErrHandlerNotFound          = errors.New("handler not found")
	ErrHandlerAlreadyRegistered = errors.New("handler already registered")
	ErrRegisterUserNotSupported = errors.New("register user not supported")
	ErrLoginNotSupported        = errors.New("login not supported")
	ErrLogoutNotSupported       = errors.New("logout not supported")
	ErrIssueTokenNotSupported   = errors.New("issue token not supported")
	ErrRefreshTokenNotSupported = errors.New("refresh token not supported")
	ErrRevokeTokenNotSupported  = errors.New("revoke token not supported")
)

// Manager orchestrates one or more named authentication handlers.
type Manager struct {
	mu             sync.RWMutex
	handlers       map[string]AnyHandler
	defaultHandler string
}

var (
	_ AnyHandler            = (*Manager)(nil)
	_ UserRegisterer[any]   = (*Manager)(nil)
	_ LoginHandler[any]     = (*Manager)(nil)
	_ LogoutHandler         = (*Manager)(nil)
	_ TokenIssuer[any, any] = (*Manager)(nil)
	_ TokenRefresher[any]   = (*Manager)(nil)
	_ TokenRevoker          = (*Manager)(nil)
)

// New creates a Manager and registers a "default" handler.
// Optionally accepts a HandlerOption to override the default driver or user provider.
func New(option ...HandlerOption) *Manager {
	m := &Manager{
		handlers:       make(map[string]AnyHandler),
		defaultHandler: "",
	}

	var o HandlerOption
	if len(option) > 0 {
		o = option[0]
	}

	if o.Driver == nil {
		// A random key per process: tokens don't survive restarts. Pass your own driver to persist them.
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		o.Driver = NewJWTDriver(key)
	}
	if o.UserProvider == nil {
		o.UserProvider = NewMemoryUserProvider()
	}

	_ = m.Extend("default", o)

	return m
}

// RegisterUser delegates user registration to the default handler if supported.
func (a *Manager) RegisterUser(ctx context.Context, user any) (any, error) {
	if h, ok := a.defaultH().(UserRegisterer[any]); ok {
		return h.RegisterUser(ctx, user)
	}

	return nil, ErrRegisterUserNotSupported
}

// Authenticate delegates credential-based authentication to the default handler.
func (a *Manager) Authenticate(ctx context.Context, creds any) (any, error) {
	return a.defaultH().Authenticate(ctx, creds)
}

// Validate delegates proof validation (e.g., token/session) to the default handler.
func (a *Manager) Validate(ctx context.Context, proof any) (Verified[any], error) {
	return a.defaultH().Validate(ctx, proof)
}

// Login delegates login to the default handler if supported.
func (a *Manager) Login(ctx context.Context, user any) (string, error) {
	if h, ok := a.defaultH().(LoginHandler[any]); ok {
		return h.Login(ctx, user)
	}

	return "", ErrLoginNotSupported
}

// Logout delegates logout to the default handler if supported.
func (a *Manager) Logout(ctx context.Context, sessionID string) error {
	if h, ok := a.defaultH().(LogoutHandler); ok {
		return h.Logout(ctx, sessionID)
	}

	return ErrLogoutNotSupported
}

// IssueToken delegates token issuance to the default handler if supported.
func (a *Manager) IssueToken(ctx context.Context, user any) (any, error) {
	if h, ok := a.defaultH().(TokenIssuer[any, any]); ok {
		return h.IssueToken(ctx, user)
	}
	return nil, ErrIssueTokenNotSupported
}

// RefreshToken delegates token refreshing to the default handler if supported.
func (a *Manager) RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	if h, ok := a.defaultH().(TokenRefresher[any]); ok {
		return h.RefreshToken(ctx, refreshToken)
	}
	return nil, ErrRefreshTokenNotSupported
}

// RevokeToken delegates token revocation to the default handler if supported.
func (a *Manager) RevokeToken(ctx context.Context, token string) error {
	if h, ok := a.defaultH().(TokenRevoker); ok {
		return h.RevokeToken(ctx, token)
	}
	return ErrRevokeTokenNotSupported
}

// defaultH returns the default handler, reading its name and the map under one lock.
func (a *Manager) defaultH() AnyHandler {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if h, ok := a.handlers[a.defaultHandler]; ok {
		return h
	}
	panic(fmt.Sprintf("handler '%s' not found", a.defaultHandler))
}

// LookupHandler returns a named handler or ErrHandlerNotFound if it does not exist.
func (a *Manager) LookupHandler(name string) (AnyHandler, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if g, ok := a.handlers[name]; ok {
		return g, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrHandlerNotFound, name)
}

// MustHandler returns a named handler, panicking if it does not exist.
// Useful for startup code where handlers are expected to be present.
func (a *Manager) MustHandler(name string) AnyHandler {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if g, ok := a.handlers[name]; ok {
		return g
	}

	panic(fmt.Sprintf("handler '%s' not found", name))
}

// RegisterHandler registers a new handler under the given name.
// The first handler registered becomes the default and will return an error
// if the handler name already exists.
func (a *Manager) RegisterHandler(name string, handler AnyHandler) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.handlers[name]; ok {
		return fmt.Errorf("%w: %s", ErrHandlerAlreadyRegistered, name)
	}

	// set the first handler as default
	if len(a.handlers) == 0 {
		a.defaultHandler = name
	}

	a.handlers[name] = handler
	return nil
}

// Extend registers or replaces a handler under the given name.
// The first handler registered becomes the default.
func (a *Manager) Extend(name string, option HandlerOption) error {
	if option.UserProvider == nil || option.Driver == nil {
		panic("UserProvider or Validator cannot be nil")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// set the first handler as default
	if len(a.handlers) == 0 {
		a.defaultHandler = name
	}

	a.handlers[name] = NewBaseAuth(option.UserProvider, option.Driver)

	return nil
}

// SetDefault sets the default handler to the named handler, returning an error if not found.
func (a *Manager) SetDefault(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.handlers[name]; !ok {
		return fmt.Errorf("%w: %s", ErrHandlerNotFound, name)
	}

	a.defaultHandler = name
	return nil
}

// Verified holds the result of a successful proof validation,
// containing the authenticated user and optional permissions.
type Verified[U any] struct {
	User        U
	Permissions []string
}

// HandlerOption configures a handler by supplying a Validator and UserProvider.
type HandlerOption struct {
	Driver       Validator[any, any]
	UserProvider UserProvider[any, any]
}

var (
	defaultAuth *Manager
	once        sync.Once
)

// getManager returns the singleton default Manager, initializing it once.
func getManager() *Manager {
	once.Do(func() {
		defaultAuth = New()
	})
	return defaultAuth
}

// Package-level convenience functions (facade) using the default Manager:

// RegisterUser registers a new user using the default handler.
func RegisterUser(ctx context.Context, user any) (any, error) {
	return getManager().RegisterUser(ctx, user)
}

// Authenticate authenticates credentials using the default handler.
func Authenticate(ctx context.Context, creds any) (any, error) {
	return getManager().Authenticate(ctx, creds)
}

// Validate validates a proof (token/session) using the default handler.
func Validate(ctx context.Context, proof any) (Verified[any], error) {
	return getManager().Validate(ctx, proof)
}

// Login logs in a user using the default handler.
func Login(ctx context.Context, user any) (string, error) {
	return getManager().Login(ctx, user)
}

// Logout logs out a session using the default handler.
func Logout(ctx context.Context, sessionID string) error {
	return getManager().Logout(ctx, sessionID)
}

// IssueToken issues a token using the default handler.
func IssueToken(ctx context.Context, user any) (any, error) {
	return getManager().IssueToken(ctx, user)
}

// RefreshToken refreshes a token using the default handler.
func RefreshToken(ctx context.Context, refreshToken string) (any, error) {
	return getManager().RefreshToken(ctx, refreshToken)
}

// RevokeToken revokes a token using the default handler.
func RevokeToken(ctx context.Context, token string) error {
	return getManager().RevokeToken(ctx, token)
}

// LookupHandler finds a named handler using the default Manager.
func LookupHandler(name string) (AnyHandler, error) {
	return getManager().LookupHandler(name)
}

// MustHandler finds a named handler or panics if not present.
func MustHandler(name string) AnyHandler {
	return getManager().MustHandler(name)
}

// RegisterHandler registers a new named handler on the default Manager
func RegisterHandler(name string, handler AnyHandler) error {
	return getManager().RegisterHandler(name, handler)
}

// Extend registers or replaces a named handler on the default Manager.
func Extend(name string, option HandlerOption) error {
	return getManager().Extend(name, option)
}

// SetDefault sets the default handler on the default Manager.
func SetDefault(name string) error {
	return getManager().SetDefault(name)
}

// UseDriver replaces the Validator on the default handler (preserving user provider).
func UseDriver(driver Validator[any, any]) {
	m := getManager()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Swap in a new handler instead of changing fields that in-flight requests read without a lock.
	if h, ok := m.handlers[m.defaultHandler].(*BaseAuth[any, any, any]); ok {
		m.handlers[m.defaultHandler] = NewBaseAuth(h.userProvider, driver)
	}
}

// UseUserProvider replaces the UserProvider on the default handler (preserving driver).
func UseUserProvider(provider UserProvider[any, any]) {
	m := getManager()

	m.mu.Lock()
	defer m.mu.Unlock()

	if h, ok := m.handlers[m.defaultHandler].(*BaseAuth[any, any, any]); ok {
		m.handlers[m.defaultHandler] = NewBaseAuth(provider, h.driver)
	}
}
