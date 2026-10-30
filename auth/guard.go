package auth

import (
	"context"
	"errors"
	"fmt"
)

// Errors every TokenGuard adapter must match with errors.Is. Any other error is an internal failure.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidToken       = errors.New("invalid token")
)

// kindError keeps a specific error's own message while making it match one of the errors above.
type kindError struct {
	msg  string
	kind error
}

func (e *kindError) Error() string { return e.msg }
func (e *kindError) Unwrap() error { return e.kind }

// TokenProvider issues, refreshes and verifies tokens for a user identity.
//
// ID - user identity carried by the token
// T  - what gets issued (a single token, or an access/refresh pair)
type TokenProvider[ID, T any] interface {
	Issue(ctx context.Context, id ID) (T, error)
	// Refresh exchanges a refresh token for new tokens. A refresh token can be used once.
	Refresh(ctx context.Context, refreshToken string) (T, error)
	Verify(ctx context.Context, bearer string) (ID, error)
}

// TokenGuard is the typed token-auth path: log in with credentials, refresh, and verify bearer tokens.
//
// Errors pass through unchanged. Adapters must return errors matching ErrInvalidCredentials
// (bad credentials), ErrTokenExpired (expired bearer token) or ErrInvalidToken (any other
// rejected bearer or refresh token); anything else means an internal failure.
type TokenGuard[C, ID, T any] struct {
	users  UserProvider[C, ID]
	tokens TokenProvider[ID, T]
}

// NewTokenGuard creates a TokenGuard. It panics if users or tokens is nil.
func NewTokenGuard[C, ID, T any](users UserProvider[C, ID], tokens TokenProvider[ID, T]) *TokenGuard[C, ID, T] {
	if users == nil || tokens == nil {
		panic("auth: TokenGuard needs a UserProvider and a TokenProvider")
	}
	return &TokenGuard[C, ID, T]{users: users, tokens: tokens}
}

// Login checks credentials and issues tokens for the user.
func (g *TokenGuard[C, ID, T]) Login(ctx context.Context, creds C) (T, error) {
	id, err := g.users.FindByCredentials(ctx, creds)
	if err != nil {
		var zero T
		return zero, err
	}
	return g.tokens.Issue(ctx, id)
}

// Refresh exchanges a refresh token for new tokens.
func (g *TokenGuard[C, ID, T]) Refresh(ctx context.Context, refreshToken string) (T, error) {
	return g.tokens.Refresh(ctx, refreshToken)
}

// Verify returns the user identity carried by a bearer token.
func (g *TokenGuard[C, ID, T]) Verify(ctx context.Context, bearer string) (ID, error) {
	return g.tokens.Verify(ctx, bearer)
}

// JWTTokens adapts JWTDriver to TokenProvider. The token is its own refresh token (see JWTDriver.RefreshToken).
type JWTTokens struct {
	d *JWTDriver
}

var _ TokenProvider[string, string] = (*JWTTokens)(nil)

// NewJWTTokens creates a JWTTokens that issues and verifies tokens with d.
func NewJWTTokens(d *JWTDriver) *JWTTokens {
	return &JWTTokens{d: d}
}

// Issue returns a new JWT for userID.
func (t *JWTTokens) Issue(ctx context.Context, userID string) (string, error) {
	tok, err := t.d.IssueToken(ctx, &User{ID: userID})
	if err != nil {
		return "", err
	}
	return tok.(string), nil
}

// Refresh exchanges a valid token for a new one and revokes the old one.
func (t *JWTTokens) Refresh(ctx context.Context, refreshToken string) (string, error) {
	tok, err := t.d.RefreshToken(ctx, refreshToken)
	if err != nil {
		// an expired login can't be refreshed, so it's an invalid refresh token, not an expired bearer
		if errors.Is(err, ErrTokenExpired) {
			return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		return "", err
	}
	return tok.(string), nil
}

// Verify returns the user ID of a valid, unrevoked JWT.
func (t *JWTTokens) Verify(ctx context.Context, bearer string) (string, error) {
	v, err := t.d.Validate(ctx, bearer)
	if err != nil {
		return "", err
	}
	return v.User.(*User).ID, nil
}
