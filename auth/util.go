package auth

import (
	"context"

	"github.com/google/uuid"
)

func uniqid() string {
	return uuid.NewString()
}

// ctxKey is a private type for context keys in this package.
type ctxKey string

const userCtxKey ctxKey = "user"

// WithUserCtx stores the authenticated user in the context.
func WithUserCtx(ctx context.Context, user any) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

// UserFromCtx retrieves the authenticated user from the context.
func UserFromCtx(ctx context.Context) any {
	return ctx.Value(userCtxKey)
}
