package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type staticUsers map[string]string // email -> password; the email is also the user ID

func (s staticUsers) FindByCredentials(_ context.Context, c PasswordCredentials) (string, error) {
	pw, ok := s[c.Email]
	if !ok {
		return "", ErrUserNotFound
	}
	if pw != c.Password {
		return "", ErrIncorrectPassword
	}
	return c.Email, nil
}

func newTestGuard() *TokenGuard[PasswordCredentials, string, string] {
	return NewTokenGuard(staticUsers{"a@example.com": "secret"}, NewJWTTokens(NewJWTDriver([]byte("test-key"))))
}

func TestTokenGuard_LoginRefreshVerify(t *testing.T) {
	ctx := context.Background()
	g := newTestGuard()

	tok, err := g.Login(ctx, PasswordCredentials{Email: "a@example.com", Password: "secret"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if id, err := g.Verify(ctx, tok); err != nil || id != "a@example.com" {
		t.Fatalf("Verify = %q, %v", id, err)
	}

	newTok, err := g.Refresh(ctx, tok)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := g.Refresh(ctx, tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("reused refresh token: got %v, want ErrInvalidToken", err)
	}
	if _, err := g.Verify(ctx, tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("old token after refresh: got %v, want ErrInvalidToken", err)
	}
	if id, err := g.Verify(ctx, newTok); err != nil || id != "a@example.com" {
		t.Errorf("Verify new token = %q, %v", id, err)
	}
}

func TestTokenGuard_Errors(t *testing.T) {
	ctx := context.Background()
	g := newTestGuard()

	for _, c := range []PasswordCredentials{{Email: "a@example.com", Password: "wrong"}, {Email: "b@example.com", Password: "secret"}} {
		if _, err := g.Login(ctx, c); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Login(%s): got %v, want ErrInvalidCredentials", c.Email, err)
		}
	}

	if _, err := g.Verify(ctx, "garbage"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("garbage bearer: got %v, want ErrInvalidToken", err)
	}

	d := NewJWTDriver([]byte("test-key"))
	c := Claims{UserID: "u1", AuthTime: jwt.NewNumericDate(time.Now())}
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTokenGuard(staticUsers{}, NewJWTTokens(d)).Verify(ctx, expired); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired bearer: got %v, want ErrTokenExpired", err)
	}
	if _, err := NewTokenGuard(staticUsers{}, NewJWTTokens(d)).Refresh(ctx, expired); !errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired refresh: got %v, want ErrInvalidToken only", err)
	}
}
