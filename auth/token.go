package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Errors returned by JWTDriver.
var (
	ErrJWTExpired = errors.New("JWT is expired")
	ErrJWTInvalid = errors.New("JWT is invalid")
	ErrJWTRevoked = errors.New("JWT is revoked")
)

// TokenDriver defines the contract for token-based authentication drivers.
// U is the user type, P is the token type (e.g., string or JWT container).
// Drivers must implement Validate (from Validator), and IssueToken to generate tokens.
type TokenDriver[U, P any] interface {
	Validator[U, P]
	IssueToken(ctx context.Context, user U) (P, error)
}

const (
	jwtTTL = 15 * time.Minute
	// jwtMaxLoginAge caps how long RefreshToken can extend one login before the user must sign in again.
	jwtMaxLoginAge = 7 * 24 * time.Hour
	// sweepInterval limits how often expired entries are removed, so the O(n) scan can't run on every call.
	sweepInterval = time.Minute
)

// Claims represents the JWT payload structure used by JWTDriver.
type Claims struct {
	UserID   string
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"` // when the user logged in; kept across refreshes
	jwt.RegisteredClaims
}

// JWTDriver is a JWT-based TokenDriver signed with HMAC-SHA256.
// Revoked token IDs are kept in memory until the token would expire anyway,
// so revocations are lost on restart and not shared between processes.
type JWTDriver struct {
	verifyKey []byte

	mu        sync.Mutex
	revoked   map[string]time.Time // token ID -> token expiry
	lastSweep time.Time
}

var (
	_ TokenDriver[any, any] = (*JWTDriver)(nil)
	_ TokenRefresher[any]   = (*JWTDriver)(nil)
	_ TokenRevoker          = (*JWTDriver)(nil)
)

// NewJWTDriver creates a JWTDriver that signs and verifies tokens with key.
// It panics if key is empty.
func NewJWTDriver(key []byte) *JWTDriver {
	if len(key) == 0 {
		panic("auth: JWT key must not be empty")
	}
	return &JWTDriver{
		verifyKey: key,
		revoked:   make(map[string]time.Time),
	}
}

// Sign generates a signed JWT string and returns its expiration time.
// authTime is when the user logged in; RefreshToken refuses tokens older than jwtMaxLoginAge.
func (d *JWTDriver) Sign(uid string, authTime time.Time) (string, time.Time, error) {
	now := time.Now()

	c := Claims{}
	c.UserID = uid
	c.AuthTime = jwt.NewNumericDate(authTime)
	c.ID = uniqid()
	c.IssuedAt = jwt.NewNumericDate(now)
	c.ExpiresAt = jwt.NewNumericDate(now.Add(jwtTTL))
	c.NotBefore = jwt.NewNumericDate(now)

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	signed, err := tok.SignedString(d.verifyKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing token: %w", err)
	}

	return signed, c.ExpiresAt.Time, nil
}

// Parse validates and decodes a JWT string into Claims.
// Every error matches ErrJWTExpired or ErrJWTInvalid.
// It does not check revocation; Validate does.
func (d *JWTDriver) Parse(tokenStr string) (Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(*jwt.Token) (any, error) {
		return d.verifyKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenMalformed):
			return Claims{}, ErrJWTInvalid
		case errors.Is(err, jwt.ErrTokenExpired):
			return Claims{}, ErrJWTExpired
		default:
			return Claims{}, fmt.Errorf("%w: %w", ErrJWTInvalid, err)
		}
	}

	if c, ok := tok.Claims.(*Claims); ok {
		return *c, nil
	}

	return Claims{}, ErrJWTInvalid
}

// IssueToken creates a JWT for the given user (expected as *User).
func (d *JWTDriver) IssueToken(_ context.Context, usr any) (any, error) {
	u, ok := usr.(*User)
	if !ok || u.ID == "" {
		return nil, ErrInvalidUser
	}

	jwtStr, _, err := d.Sign(u.ID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	return jwtStr, nil
}

// Validate parses and validates the JWT, returning a Verified[any] with the user.
func (d *JWTDriver) Validate(_ context.Context, proof any) (Verified[any], error) {
	token, ok := proof.(string)
	if !ok {
		return Verified[any]{}, ErrJWTInvalid
	}

	claims, err := d.Parse(token)
	if err != nil {
		return Verified[any]{}, fmt.Errorf("parse token: %w", err)
	}

	d.mu.Lock()
	_, revoked := d.revoked[claims.ID]
	d.mu.Unlock()
	if revoked {
		return Verified[any]{}, ErrJWTRevoked
	}

	return Verified[any]{
		User: &User{ID: claims.UserID},
	}, nil
}

// RefreshToken exchanges a valid, unexpired token for a new one and revokes the old one.
// There is no separate long-lived refresh token: a client must refresh before expiry,
// and must log in again once the original login is older than jwtMaxLoginAge.
func (d *JWTDriver) RefreshToken(_ context.Context, token string) (any, error) {
	claims, err := d.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if claims.AuthTime == nil || time.Since(claims.AuthTime.Time) > jwtMaxLoginAge {
		return nil, ErrJWTExpired
	}

	if !d.revoke(claims) {
		return nil, ErrJWTRevoked
	}

	jwtStr, _, err := d.Sign(claims.UserID, claims.AuthTime.Time)
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	return jwtStr, nil
}

// RevokeToken makes a token unusable before it expires. Expired tokens are a no-op.
func (d *JWTDriver) RevokeToken(_ context.Context, token string) error {
	claims, err := d.Parse(token)
	if errors.Is(err, ErrJWTExpired) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("parse token: %w", err)
	}

	d.revoke(claims)
	return nil
}

// revoke records the token ID as revoked. It returns false if it already was,
// so concurrent refreshes of the same token can't both succeed.
func (d *JWTDriver) revoke(c Claims) bool {
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	// shortcut: in-memory and per process, so revocations aren't shared between instances; use a shared store for that.
	if now.Sub(d.lastSweep) > sweepInterval {
		for id, exp := range d.revoked {
			if now.After(exp) {
				delete(d.revoked, id)
			}
		}
		d.lastSweep = now
	}

	if _, ok := d.revoked[c.ID]; ok {
		return false
	}
	d.revoked[c.ID] = c.ExpiresAt.Time
	return true
}
