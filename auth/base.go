package auth

import (
	"context"
	"fmt"
)

// BaseAuth is the authentication handler. It connects a user provider and a
// driver. Optional capabilities (registration, login/logout, token issue,
// refresh, revoke) are delegated when the provider or driver implements them,
// and return the matching ErrXxxNotSupported error otherwise.
//
// C - Credential type (e.g., struct with email/password)
// U - User type
// P - Proof type (e.g., token, session ID)
type BaseAuth[C, U, P any] struct {
	driver       Validator[U, P]    // Responsible for validating the proof (e.g., token/session ID)
	userProvider UserProvider[C, U] // Responsible for locating and authenticating users by credentials
}

var (
	_ AnyHandler            = (*BaseAuth[any, any, any])(nil)
	_ UserRegisterer[any]   = (*BaseAuth[any, any, any])(nil)
	_ LoginHandler[any]     = (*BaseAuth[any, any, any])(nil)
	_ LogoutHandler         = (*BaseAuth[any, any, any])(nil)
	_ TokenIssuer[any, any] = (*BaseAuth[any, any, any])(nil)
	_ TokenRefresher[any]   = (*BaseAuth[any, any, any])(nil)
	_ TokenRevoker          = (*BaseAuth[any, any, any])(nil)
)

// NewBaseAuth creates a new BaseAuth instance with the provided
// user provider and driver.
func NewBaseAuth[C, U, P any](userProvider UserProvider[C, U], driver Validator[U, P]) *BaseAuth[C, U, P] {
	return &BaseAuth[C, U, P]{
		driver:       driver,
		userProvider: userProvider,
	}
}

// NewSessionAuth creates a BaseAuth whose driver is checked at compile time to support Login/Logout.
func NewSessionAuth[C, U, P any, D SessionDriver[U, P], UP UserProvider[C, U]](driver D, userProvider UP) *BaseAuth[C, U, P] {
	return NewBaseAuth[C, U, P](userProvider, driver)
}

// NewTokenAuth creates a BaseAuth whose driver is checked at compile time to support IssueToken.
func NewTokenAuth[C, U, P any, D TokenDriver[U, P], UP UserProvider[C, U]](driver D, userProvider UP) *BaseAuth[C, U, P] {
	return NewBaseAuth[C, U, P](userProvider, driver)
}

// Authenticate attempts to find and return a user based on the
// provided credentials. Delegates to the UserProvider.
func (a *BaseAuth[C, U, P]) Authenticate(ctx context.Context, creds C) (U, error) {
	return a.userProvider.FindByCredentials(ctx, creds)
}

// Validate checks the authenticity of a proof (e.g., token/session ID)
// and returns the verified user context. Delegates to the Validator.
func (a *BaseAuth[C, U, P]) Validate(ctx context.Context, proof P) (Verified[U], error) {
	return a.driver.Validate(ctx, proof)
}

// RegisterUser delegates to the user provider if it implements UserRegisterer.
func (a *BaseAuth[C, U, P]) RegisterUser(ctx context.Context, user U) (U, error) {
	if r, ok := a.userProvider.(UserRegisterer[U]); ok {
		return r.RegisterUser(ctx, user)
	}
	var zero U
	return zero, ErrRegisterUserNotSupported
}

// Attempt combines Authenticate and Login: it verifies credentials and creates a session.
func (a *BaseAuth[C, U, P]) Attempt(ctx context.Context, creds C) (U, string, error) {
	user, err := a.Authenticate(ctx, creds)
	if err != nil {
		return user, "", fmt.Errorf("authenticate: %w", err)
	}

	sess, err := a.Login(ctx, user)
	if err != nil {
		return user, "", fmt.Errorf("login: %w", err)
	}

	return user, sess, nil
}

// Login delegates to the driver if it implements LoginHandler.
func (a *BaseAuth[C, U, P]) Login(ctx context.Context, user U) (string, error) {
	if d, ok := a.driver.(LoginHandler[U]); ok {
		return d.Login(ctx, user)
	}
	return "", ErrLoginNotSupported
}

// Logout delegates to the driver if it implements LogoutHandler.
func (a *BaseAuth[C, U, P]) Logout(ctx context.Context, sessionID string) error {
	if d, ok := a.driver.(LogoutHandler); ok {
		return d.Logout(ctx, sessionID)
	}
	return ErrLogoutNotSupported
}

// IssueToken delegates to the driver if it implements TokenIssuer.
func (a *BaseAuth[C, U, P]) IssueToken(ctx context.Context, user U) (P, error) {
	if d, ok := a.driver.(TokenIssuer[U, P]); ok {
		return d.IssueToken(ctx, user)
	}
	var zero P
	return zero, ErrIssueTokenNotSupported
}

// RefreshToken delegates to the driver if it implements TokenRefresher.
func (a *BaseAuth[C, U, P]) RefreshToken(ctx context.Context, token string) (P, error) {
	if d, ok := a.driver.(TokenRefresher[P]); ok {
		return d.RefreshToken(ctx, token)
	}
	var zero P
	return zero, ErrRefreshTokenNotSupported
}

// RevokeToken delegates to the driver if it implements TokenRevoker.
func (a *BaseAuth[C, U, P]) RevokeToken(ctx context.Context, token string) error {
	if d, ok := a.driver.(TokenRevoker); ok {
		return d.RevokeToken(ctx, token)
	}
	return ErrRevokeTokenNotSupported
}
