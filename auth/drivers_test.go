package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTDriver_RevokeAndRefresh(t *testing.T) {
	ctx := context.Background()
	d := NewJWTDriver([]byte("test-key"))

	tok, err := d.IssueToken(ctx, &User{ID: "u1"})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	v, err := d.Validate(ctx, tok)
	if err != nil || v.User.(*User).ID != "u1" {
		t.Fatalf("Validate = %v, %v", v, err)
	}

	newTok, err := d.RefreshToken(ctx, tok.(string))
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if _, err := d.Validate(ctx, tok); !errors.Is(err, ErrJWTRevoked) {
		t.Errorf("old token after refresh: got %v, want ErrJWTRevoked", err)
	}
	if _, err := d.RefreshToken(ctx, tok.(string)); !errors.Is(err, ErrJWTRevoked) {
		t.Errorf("second refresh of same token: got %v, want ErrJWTRevoked", err)
	}

	if err := d.RevokeToken(ctx, newTok.(string)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := d.Validate(ctx, newTok); !errors.Is(err, ErrJWTRevoked) {
		t.Errorf("revoked token: got %v, want ErrJWTRevoked", err)
	}
}

func TestJWTDriver_RejectsForeignTokens(t *testing.T) {
	ctx := context.Background()
	d := NewJWTDriver([]byte("test-key"))

	other, _, _ := NewJWTDriver([]byte("other-key")).Sign("u1", time.Now())
	if _, err := d.Validate(ctx, other); !errors.Is(err, ErrJWTInvalid) {
		t.Errorf("wrong key: got %v, want ErrJWTInvalid", err)
	}

	c := Claims{UserID: "u1"}
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	hs512, _ := jwt.NewWithClaims(jwt.SigningMethodHS512, c).SignedString([]byte("test-key"))
	if _, err := d.Validate(ctx, hs512); !errors.Is(err, ErrJWTInvalid) {
		t.Errorf("unexpected alg: got %v, want ErrJWTInvalid", err)
	}
}

func TestMemorySessionDriver_RemovesExpiredSessions(t *testing.T) {
	ctx := context.Background()
	d := NewMemorySessionDriver()

	stale, _ := d.Login(ctx, &User{ID: "u1"})
	d.sessions[stale] = session{uid: "u1", exp: time.Now().Add(-time.Second)}

	if _, err := d.Validate(ctx, stale); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("got %v, want ErrSessionExpired", err)
	}
	if _, ok := d.sessions[stale]; ok {
		t.Error("expired session kept after Validate")
	}

	abandoned, _ := d.Login(ctx, &User{ID: "u2"})
	d.sessions[abandoned] = session{uid: "u2", exp: time.Now().Add(-time.Second)}
	d.lastSweep = time.Time{}
	if _, err := d.Login(ctx, &User{ID: "u3"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.sessions[abandoned]; ok {
		t.Error("expired session kept after Login sweep")
	}
}

func TestMemoryUserProvider_HashesPasswords(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryUserProvider()

	in := &User{Email: "a@example.com", Password: "secret"}
	out, err := p.RegisterUser(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if in.ID != "" || in.Password != "secret" {
		t.Errorf("RegisterUser modified its argument: %+v", in)
	}
	if out.(*User).Password == "secret" {
		t.Error("password stored in plain text")
	}

	if _, err := p.FindByCredentials(ctx, PasswordCredentials{Email: "a@example.com", Password: "secret"}); err != nil {
		t.Errorf("correct password: %v", err)
	}
	if _, err := p.FindByCredentials(ctx, PasswordCredentials{Email: "a@example.com", Password: "wrong"}); !errors.Is(err, ErrIncorrectPassword) {
		t.Errorf("wrong password: got %v, want ErrIncorrectPassword", err)
	}
}

func TestJWTDriver_RefreshStopsAfterMaxLoginAge(t *testing.T) {
	d := NewJWTDriver([]byte("test-key"))
	old, _, err := d.Sign("u1", time.Now().Add(-jwtMaxLoginAge-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RefreshToken(context.Background(), old); !errors.Is(err, ErrJWTExpired) {
		t.Errorf("got %v, want ErrJWTExpired", err)
	}
}

func TestJWTDriver_ParseErrorsAreTyped(t *testing.T) {
	d := NewJWTDriver([]byte("test-key"))
	noExp, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{UserID: "u1"}).SignedString([]byte("test-key"))
	if _, err := d.Parse(noExp); !errors.Is(err, ErrJWTInvalid) {
		t.Errorf("token without exp: got %v, want ErrJWTInvalid", err)
	}
}

func TestMemoryUserProvider_EmailIsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryUserProvider()
	if _, err := p.RegisterUser(ctx, &User{Email: "A@Example.com", Password: "secret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RegisterUser(ctx, &User{Email: "a@example.com", Password: "secret"}); !errors.Is(err, ErrUserAlreadyExists) {
		t.Errorf("got %v, want ErrUserAlreadyExists", err)
	}
	if _, err := p.FindByCredentials(ctx, PasswordCredentials{Email: "a@EXAMPLE.com", Password: "secret"}); err != nil {
		t.Errorf("login with different case: %v", err)
	}
}

// Run with -race: SetDefault and UseDriver-style swaps must not race with requests.
func TestManager_ConcurrentSetDefaultAndValidate(t *testing.T) {
	m := New()
	if err := m.Extend("other", HandlerOption{Driver: NewJWTDriver([]byte("k")), UserProvider: NewMemoryUserProvider()}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			_ = m.SetDefault("other")
			_ = m.SetDefault("default")
		}
	}()
	for range 100 {
		_, _ = m.Validate(context.Background(), "token")
	}
	<-done
}
