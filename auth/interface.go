package auth

import (
	"context"
)

// UserProvider represents a user lookup service using provided credentials.
type UserProvider[C, U any] interface {
	FindByCredentials(ctx context.Context, creds C) (U, error)
}

// Authenticator defines a single responsibility interface for authenticating users
// using provided credentials.
type Authenticator[C, U any] interface {
	Authenticate(ctx context.Context, creds C) (U, error)
}

// Validator defines a component capable of validating a proof (e.g., token, session ID)
// and returning a verified user context.
type Validator[U, P any] interface {
	Validate(ctx context.Context, proof P) (Verified[U], error)
}

// UserRegisterer defines a contract for registering new users.
type UserRegisterer[U any] interface {
	RegisterUser(context.Context, U) (U, error)
}

// LoginHandler defines an interface for logging in a user and returning a session ID.
type LoginHandler[U any] interface {
	Login(ctx context.Context, user U) (string, error)
}

// LogoutHandler defines an interface for logging out a user by session ID.
type LogoutHandler interface {
	Logout(context.Context, string) error
}

// TokenIssuer defines an interface for issuing tokens for a given user.
type TokenIssuer[U, P any] interface {
	IssueToken(ctx context.Context, user U) (P, error)
}

// TokenRefresher defines an interface for refreshing tokens using a refresh token string.
type TokenRefresher[P any] interface {
	RefreshToken(ctx context.Context, refreshToken string) (P, error)
}

// TokenRevoker defines an interface for explicitly revoking a token.
type TokenRevoker interface {
	RevokeToken(ctx context.Context, token string) error
}

// Handler is a generic interface that combines authentication and validation
// behavior using a credential and proof system.
type Handler[C, U, P any] interface {
	Authenticator[C, U]
	Validator[U, P]
}

// AnyHandler is a convenience alias for a fully dynamic, untyped handler.
type AnyHandler = Handler[any, any, any]
