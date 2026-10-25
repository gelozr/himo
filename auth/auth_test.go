package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gelozr/himo/auth"
)

type MockUser struct {
	ID any
}
type MockUserProvider struct {
	shouldFailCredentials   bool
	user                    *MockUser
	findByCredentialsCalled bool
}

func (m *MockUserProvider) FindByCredentials(_ context.Context, _ any) (any, error) {
	m.findByCredentialsCalled = true

	if m.shouldFailCredentials {
		return nil, errors.New("credentials error")
	}

	return m.user, nil
}

type MockUserProviderWithRegister struct {
	MockUserProvider
	shouldFailRegister bool
	registerCalled     bool
}

func (m *MockUserProviderWithRegister) RegisterUser(_ context.Context, _ any) (any, error) {
	m.registerCalled = true

	if m.shouldFailRegister {
		return nil, errors.New("register error")
	}

	return m.user, nil
}

type MockDriver struct {
	shouldFailValidate bool
	validateCalled     bool
	user               *MockUser
}

func (m *MockDriver) Validate(_ context.Context, _ any) (auth.Verified[any], error) {
	m.validateCalled = true

	var v auth.Verified[any]

	if m.shouldFailValidate {
		return v, errors.New("mock error")
	}

	v.User = m.user
	return v, nil
}

type MockSessionDriver struct {
	MockDriver
	loginCalled      bool
	logoutCalled     bool
	shouldFailLogin  bool
	shouldFailLogout bool
}

func (m *MockSessionDriver) Login(_ context.Context, _ any) (string, error) {
	m.loginCalled = true

	if m.shouldFailLogin {
		return "", errors.New("mock error login")
	}
	return "sessionID", nil
}

func (m *MockSessionDriver) Logout(_ context.Context, _ string) error {
	m.logoutCalled = true

	if m.shouldFailLogout {
		return errors.New("mock error logout")
	}

	return nil
}

type MockTokenDriver struct {
	MockDriver
	issueTokenCalled     bool
	shouldFailIssueToken bool
}

func (m *MockTokenDriver) IssueToken(_ context.Context, _ any) (any, error) {
	m.issueTokenCalled = true

	if m.shouldFailIssueToken {
		return nil, errors.New("mock error issue token")
	}

	return "token", nil
}

type MockTokenRefresherDriver struct {
	MockTokenDriver
	refreshTokenCalled     bool
	shouldFailRefreshToken bool
}

func (m *MockTokenRefresherDriver) RefreshToken(_ context.Context, _ string) (any, error) {
	m.refreshTokenCalled = true

	if m.shouldFailRefreshToken {
		return nil, errors.New("mock error refresh token")
	}

	return "token", nil
}

type MockTokenRevokerDriver struct {
	MockTokenDriver
	revokeTokenCalled     bool
	shouldFailRevokeToken bool
}

func (m *MockTokenRevokerDriver) RevokeToken(_ context.Context, _ string) error {
	m.revokeTokenCalled = true

	if m.shouldFailRevokeToken {
		return errors.New("mock error revoke token")
	}

	return nil
}

type MockHandler struct {
	authenticateCalled     bool
	validateCalled         bool
	shouldFailAuthenticate bool
	shouldFailValidate     bool
	user                   *MockUser
}

func (m *MockHandler) Authenticate(_ context.Context, _ any) (any, error) {
	m.authenticateCalled = true
	if m.shouldFailAuthenticate {
		return nil, errors.New("mock error authenticate")
	}
	return m.user, nil
}

func (m *MockHandler) Validate(_ context.Context, _ any) (auth.Verified[any], error) {
	m.validateCalled = true

	var v auth.Verified[any]
	if m.shouldFailValidate {
		return v, errors.New("mock error validate")
	}

	v.User = m.user
	return v, nil
}

func TestManager_New(t *testing.T) {
	t.Parallel()
	t.Run("NoOptions", func(t *testing.T) {
		t.Parallel()
		a := auth.New()
		if a == nil {
			t.Errorf("New() expected non-nil")
		}
	})

	t.Run("WithHandlerOption", func(t *testing.T) {
		t.Parallel()
		a := auth.New(auth.HandlerOption{})
		if a == nil {
			t.Errorf("New() with option expected non-nil")
		}
	})
}

func testExtend(t *testing.T, fn func(auth.HandlerOption) error) {
	tests := []struct {
		name   string
		option auth.HandlerOption
		panics bool
	}{
		{name: "valid", option: auth.HandlerOption{Driver: &MockDriver{}, UserProvider: &MockUserProvider{}}},
		{name: "panic on nil", option: auth.HandlerOption{}, panics: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.panics {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("expected panic for nil driver or user provider")
					}
				}()
			}

			if err := fn(tt.option); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestManager_Extend(t *testing.T) {
	t.Parallel()
	testExtend(t, func(opt auth.HandlerOption) error {
		a := auth.New()
		return a.Extend("test", opt)
	})
}

func Test_Extend(t *testing.T) {
	t.Parallel()
	testExtend(t, func(opt auth.HandlerOption) error {
		return auth.Extend("test", opt)
	})
}

func testSetDefault(t *testing.T, fn func(auth.HandlerOption, string) error) {
	tests := []struct {
		name    string
		handler string
		wantErr bool
	}{
		{
			name:    "handler not found",
			handler: "not found",
			wantErr: true,
		},
		{
			name:    "handler found",
			handler: "test",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := fn(auth.HandlerOption{Driver: &MockDriver{}, UserProvider: &MockUserProvider{}}, tt.handler)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetDefault() expected error = %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestManager_SetDefault(t *testing.T) {
	t.Parallel()
	testSetDefault(t, func(opt auth.HandlerOption, handler string) error {
		a := auth.New()
		if err := a.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return a.SetDefault(handler)
	})
}

func Test_SetDefault(t *testing.T) {
	// Not parallel: changes the default handler of the package-level Manager.
	testSetDefault(t, func(opt auth.HandlerOption, handler string) error {
		if err := auth.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return auth.SetDefault(handler)
	})
}

func testRegisterHandler(t *testing.T, fn func(auth.HandlerOption, string) error) {
	tests := []struct {
		name    string
		handler string
		wantErr bool
	}{
		{
			name:    "handler already registered",
			handler: "test",
			wantErr: true,
		},
		{
			name:    "handler new",
			handler: "new",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := fn(auth.HandlerOption{Driver: &MockDriver{}, UserProvider: &MockUserProvider{}}, tt.handler)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetDefault() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.wantErr && !errors.Is(err, auth.ErrHandlerAlreadyRegistered) {
				t.Errorf("SetDefault() expected error = %v, got %v", auth.ErrHandlerAlreadyRegistered, err)
			}
		})
	}
}

func TestManager_RegisterHandler(t *testing.T) {
	t.Parallel()
	testRegisterHandler(t, func(opt auth.HandlerOption, handler string) error {
		a := auth.New()
		if err := a.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return a.RegisterHandler(handler, &MockHandler{})
	})
}

func Test_RegisterHandler(t *testing.T) {
	t.Parallel()
	testRegisterHandler(t, func(opt auth.HandlerOption, handler string) error {
		if err := auth.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return auth.RegisterHandler(handler, &MockHandler{})
	})
}

func testMustHandler(t *testing.T, fn func(auth.HandlerOption, string)) {
	tests := []struct {
		name    string
		handler string
		panics  bool
	}{
		{name: "valid", handler: "test", panics: false},
		{name: "panic on not found", handler: "not found handler", panics: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.panics {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("expected panic for handler not found")
					}
				}()
			}

			fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: &MockDriver{}}, tt.handler)

		})
	}
}

func TestManager_MustHandler(t *testing.T) {
	t.Parallel()
	testMustHandler(t, func(opt auth.HandlerOption, handler string) {
		a := auth.New()
		if err := a.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		a.MustHandler(handler)
	})
}

func Test_MustHandler(t *testing.T) {
	t.Parallel()
	testMustHandler(t, func(opt auth.HandlerOption, handler string) {
		if err := auth.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		auth.MustHandler(handler)
	})
}

func testLookupHandler(t *testing.T, fn func(auth.HandlerOption, string) (auth.AnyHandler, error)) {
	tests := []struct {
		name    string
		handler string
		wantErr bool
	}{
		{name: "valid", handler: "test", wantErr: false},
		{name: "error on not found", handler: "not found", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: &MockDriver{}}, tt.handler)

			if (err != nil) != tt.wantErr {
				t.Errorf("LookupHandler() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.wantErr && !errors.Is(err, auth.ErrHandlerNotFound) {
				t.Errorf("LookupHandler() expected error = %v, got %v", auth.ErrHandlerNotFound, err)
			}

			if !tt.wantErr && h == nil {
				t.Fatalf("LookupHandler() expected non-nil")
			}

		})
	}
}

func TestManager_LookupHandler(t *testing.T) {
	t.Parallel()
	testLookupHandler(t, func(opt auth.HandlerOption, handler string) (auth.AnyHandler, error) {
		a := auth.New()
		if err := a.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return a.LookupHandler(handler)
	})
}

func Test_LookupHandler(t *testing.T) {
	t.Parallel()
	testLookupHandler(t, func(opt auth.HandlerOption, handler string) (auth.AnyHandler, error) {
		if err := auth.Extend("test", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		return auth.LookupHandler(handler)
	})
}

func testRegisterUser(t *testing.T, fn func(auth.HandlerOption, context.Context, *MockUser) (any, error)) {
	tests := []struct {
		name         string
		userProvider auth.UserProvider[any, any]
		wantErr      bool
	}{
		{
			name:         "unsupported",
			userProvider: &MockUserProvider{},
			wantErr:      true,
		},
		{
			name:         "failed",
			userProvider: &MockUserProviderWithRegister{shouldFailRegister: true},
			wantErr:      true,
		},
		{
			name:         "success",
			userProvider: &MockUserProviderWithRegister{},
			wantErr:      false,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usr, err := fn(auth.HandlerOption{UserProvider: tt.userProvider, Driver: &MockDriver{}}, ctx, &MockUser{})

			if p, ok := tt.userProvider.(*MockUserProviderWithRegister); ok && !p.registerCalled {
				t.Errorf("MockUserProviderWithRegister RegisterUser() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterUser() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.name == "unsupported" && !errors.Is(err, auth.ErrRegisterUserNotSupported) {
				t.Errorf("RegisterUser() expected error = %v, got %v", auth.ErrRegisterUserNotSupported, err)
			}

			if err == nil && usr == nil {
				t.Errorf("RegisterUser() expected non-nil")
			}
		})
	}
}

func TestManager_RegisterUser(t *testing.T) {
	t.Parallel()
	testRegisterUser(t, func(opt auth.HandlerOption, ctx context.Context, user *MockUser) (any, error) {
		a := auth.New(opt)
		return a.RegisterUser(ctx, user)
	})
}

func Test_RegisterUser(t *testing.T) {
	testRegisterUser(t, func(opt auth.HandlerOption, ctx context.Context, user *MockUser) (any, error) {
		if err := auth.Extend("Test_RegisterUser", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}

		_ = auth.SetDefault("Test_RegisterUser")
		return auth.RegisterUser(ctx, user)
	})
}

func testAuthenticate(t *testing.T, fn func(auth.HandlerOption, context.Context, string) (any, error)) {
	tests := []struct {
		name         string
		userProvider *MockUserProvider
		wantErr      bool
	}{
		{
			name:         "failed authenticate",
			userProvider: &MockUserProvider{shouldFailCredentials: true, user: &MockUser{}},
			wantErr:      true,
		},
		{
			name:         "success authenticate",
			userProvider: &MockUserProvider{user: &MockUser{}},
			wantErr:      false,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := fn(auth.HandlerOption{UserProvider: tt.userProvider, Driver: &MockDriver{}}, ctx, "creds")

			if !tt.userProvider.findByCredentialsCalled {
				t.Errorf("MockUserProvider.FindByCredentials() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() expected error = %v, got %v", tt.wantErr, err)
			}

			if err == nil {
				if u == nil {
					t.Fatalf("Authenticate() expected non-nil")
				}

				usr, ok := u.(*MockUser)
				if !ok {
					t.Fatalf("Authenticate() expected mock user")
				}

				if usr == nil {
					t.Errorf("Authenticate() expected non-nil")
				}
			}
		})
	}
}

func TestManager_Authenticate(t *testing.T) {
	t.Parallel()
	testAuthenticate(t, func(opt auth.HandlerOption, ctx context.Context, creds string) (any, error) {
		a := auth.New(opt)
		return a.Authenticate(ctx, creds)
	})
}

func Test_Authenticate(t *testing.T) {
	testAuthenticate(t, func(opt auth.HandlerOption, ctx context.Context, creds string) (any, error) {
		if err := auth.Extend("Test_Authenticate", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		_ = auth.SetDefault("Test_Authenticate")

		return auth.Authenticate(ctx, creds)
	})
}

func testValidate(t *testing.T, fn func(auth.HandlerOption, context.Context, string) (auth.Verified[any], error)) {
	tests := []struct {
		name    string
		driver  *MockDriver
		wantErr bool
	}{
		{
			name:    "invalid",
			driver:  &MockDriver{shouldFailValidate: true},
			wantErr: true,
		},
		{
			name:    "valid",
			driver:  &MockDriver{user: &MockUser{ID: "verified"}},
			wantErr: false,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: tt.driver}, ctx, "proof")

			if !tt.driver.validateCalled {
				t.Errorf("MockDriver.Validate() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() expected error = %v, got %v", tt.wantErr, err)
			}

			if err == nil {
				if v.User == nil {
					t.Fatalf("Validate() expected non-nil")
				}

				_, ok := v.User.(*MockUser)
				if !ok {
					t.Fatalf("Validate() expected mock user")
				}
			}
		})
	}
}

func TestManager_Validate(t *testing.T) {
	t.Parallel()
	testValidate(t, func(opt auth.HandlerOption, ctx context.Context, proof string) (auth.Verified[any], error) {
		a := auth.New(opt)
		return a.Validate(ctx, proof)
	})
}

func Test_Validate(t *testing.T) {
	testValidate(t, func(opt auth.HandlerOption, ctx context.Context, proof string) (auth.Verified[any], error) {
		if err := auth.Extend("Test_Validate", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		_ = auth.SetDefault("Test_Validate")
		return auth.Validate(ctx, proof)
	})
}

func testLogin(t *testing.T, fn func(auth.HandlerOption, context.Context, *MockUser) (string, error)) {
	tests := []struct {
		name           string
		driver         auth.Validator[any, any]
		wantErr        bool
		expectedResult string
	}{
		{
			name:           "unsupported",
			driver:         &MockDriver{},
			wantErr:        true,
			expectedResult: "",
		},
		{
			name:           "failed",
			driver:         &MockSessionDriver{shouldFailLogin: true},
			wantErr:        true,
			expectedResult: "",
		},
		{
			name:           "success",
			driver:         &MockSessionDriver{},
			wantErr:        false,
			expectedResult: "sessionID",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: tt.driver}, ctx, &MockUser{})

			if p, ok := tt.driver.(*MockSessionDriver); ok && !p.loginCalled {
				t.Errorf("MockSessionDriver.Login() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Login() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.name == "unsupported" && !errors.Is(err, auth.ErrLoginNotSupported) {
				t.Errorf("Login() expected error = %v, got %v", auth.ErrLoginNotSupported, err)
			}

			if sess != tt.expectedResult {
				t.Errorf("Login() expected %v, got %v", tt.expectedResult, sess)
			}
		})
	}
}

func TestManager_Login(t *testing.T) {
	t.Parallel()
	testLogin(t, func(opt auth.HandlerOption, ctx context.Context, user *MockUser) (string, error) {
		a := auth.New(opt)
		return a.Login(ctx, user)
	})
}

func Test_Login(t *testing.T) {
	testLogin(t, func(opt auth.HandlerOption, ctx context.Context, user *MockUser) (string, error) {
		if err := auth.Extend("Test_Login", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		_ = auth.SetDefault("Test_Login")
		return auth.Login(ctx, user)
	})
}

func testLogout(t *testing.T, fn func(auth.HandlerOption, context.Context, string) error) {
	tests := []struct {
		name           string
		driver         auth.Validator[any, any]
		wantErr        bool
		expectedResult string
	}{
		{
			name:           "unsupported",
			driver:         &MockDriver{},
			wantErr:        true,
			expectedResult: "",
		},
		{
			name:           "failed",
			driver:         &MockSessionDriver{shouldFailLogout: true},
			wantErr:        true,
			expectedResult: "",
		},
		{
			name:           "success",
			driver:         &MockSessionDriver{},
			wantErr:        false,
			expectedResult: "sessionID",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: tt.driver}, ctx, "sessionID")

			if p, ok := tt.driver.(*MockSessionDriver); ok && !p.logoutCalled {
				t.Errorf("MockSessionDriver.Logout() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Logout() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.name == "unsupported" && !errors.Is(err, auth.ErrLogoutNotSupported) {
				t.Errorf("Logout() expected error = %v, got %v", auth.ErrLogoutNotSupported, err)
			}
		})
	}
}

func TestManager_Logout(t *testing.T) {
	t.Parallel()
	testLogout(t, func(opt auth.HandlerOption, ctx context.Context, sess string) error {
		a := auth.New(opt)
		return a.Logout(ctx, sess)
	})
}

func Test_Logout(t *testing.T) {
	testLogout(t, func(opt auth.HandlerOption, ctx context.Context, sess string) error {
		if err := auth.Extend("Test_Logout", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		_ = auth.SetDefault("Test_Logout")
		return auth.Logout(ctx, sess)
	})
}

func testIssueToken(t *testing.T, fn func(auth.HandlerOption, context.Context, *MockUser) (any, error)) {
	tests := []struct {
		name           string
		driver         auth.Validator[any, any]
		wantErr        bool
		expectedResult any
	}{
		{
			name:           "unsupported",
			driver:         &MockDriver{},
			wantErr:        true,
			expectedResult: nil,
		},
		{
			name:           "failed",
			driver:         &MockTokenDriver{shouldFailIssueToken: true},
			wantErr:        true,
			expectedResult: nil,
		},
		{
			name:           "success",
			driver:         &MockTokenDriver{},
			wantErr:        false,
			expectedResult: "token",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: tt.driver}, ctx, &MockUser{})

			if p, ok := tt.driver.(*MockTokenDriver); ok && !p.issueTokenCalled {
				t.Errorf("MockTokenDriver.IssueToken() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("IssueToken() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.name == "unsupported" && !errors.Is(err, auth.ErrIssueTokenNotSupported) {
				t.Errorf("IssueToken() expected error = %v, got %v", auth.ErrIssueTokenNotSupported, err)
			}

			if token != tt.expectedResult {
				t.Errorf("IssueToken() expected %v, got %v", tt.expectedResult, token)
			}
		})
	}
}

func TestManager_IssueToken(t *testing.T) {
	t.Parallel()
	testIssueToken(t, func(opt auth.HandlerOption, ctx context.Context, user *MockUser) (any, error) {
		a := auth.New(opt)
		return a.IssueToken(ctx, user)
	})
}

func Test_IssueToken(t *testing.T) {
	testIssueToken(t, func(opt auth.HandlerOption, ctx context.Context, user *MockUser) (any, error) {
		if err := auth.Extend("Test_IssueToken", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		_ = auth.SetDefault("Test_IssueToken")
		return auth.IssueToken(ctx, user)
	})
}

func testRefreshToken(t *testing.T, fn func(auth.HandlerOption, context.Context, string) (any, error)) {
	tests := []struct {
		name           string
		driver         auth.Validator[any, any]
		wantErr        bool
		expectedResult any
	}{
		{
			name:           "unsupported",
			driver:         &MockDriver{},
			wantErr:        true,
			expectedResult: nil,
		},
		{
			name:           "failed",
			driver:         &MockTokenRefresherDriver{shouldFailRefreshToken: true},
			wantErr:        true,
			expectedResult: nil,
		},
		{
			name:           "success",
			driver:         &MockTokenRefresherDriver{},
			wantErr:        false,
			expectedResult: "token",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: tt.driver}, ctx, "refreshToken")

			if p, ok := tt.driver.(*MockTokenRefresherDriver); ok && !p.refreshTokenCalled {
				t.Errorf("MockTokenRefresherDriver.RefreshToken() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.name == "unsupported" && !errors.Is(err, auth.ErrRefreshTokenNotSupported) {
				t.Errorf("RefreshToken() expected error = %v, got %v", auth.ErrRefreshTokenNotSupported, err)
			}

			if token != tt.expectedResult {
				t.Errorf("RefreshToken() expected %v, got %v", tt.expectedResult, token)
			}
		})
	}
}

func TestManager_RefreshToken(t *testing.T) {
	t.Parallel()
	testRefreshToken(t, func(opt auth.HandlerOption, ctx context.Context, refreshToken string) (any, error) {
		a := auth.New(opt)
		return a.RefreshToken(ctx, refreshToken)
	})
}

func Test_RefreshToken(t *testing.T) {
	testRefreshToken(t, func(opt auth.HandlerOption, ctx context.Context, refreshToken string) (any, error) {
		if err := auth.Extend("Test_RefreshToken", opt); err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		_ = auth.SetDefault("Test_RefreshToken")
		return auth.RefreshToken(ctx, refreshToken)
	})
}

func testRevokeToken(t *testing.T, fn func(auth.HandlerOption, context.Context, string) error) {
	tests := []struct {
		name    string
		driver  auth.Validator[any, any]
		wantErr bool
	}{
		{
			name:    "unsupported",
			driver:  &MockDriver{},
			wantErr: true,
		},
		{
			name:    "failed",
			driver:  &MockTokenRevokerDriver{shouldFailRevokeToken: true},
			wantErr: true,
		},
		{
			name:    "success",
			driver:  &MockTokenRevokerDriver{},
			wantErr: false,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fn(auth.HandlerOption{UserProvider: &MockUserProvider{}, Driver: tt.driver}, ctx, "token")

			if p, ok := tt.driver.(*MockTokenRevokerDriver); ok && !p.revokeTokenCalled {
				t.Errorf("MockTokenRevokerDriver.RevokeToken() expected to be called")
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("RevokeToken() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.name == "unsupported" && !errors.Is(err, auth.ErrRevokeTokenNotSupported) {
				t.Errorf("RevokeToken() expected error = %v, got %v", auth.ErrRevokeTokenNotSupported, err)
			}
		})
	}
}

func TestManager_RevokeToken(t *testing.T) {
	t.Parallel()
	testRevokeToken(t, func(opt auth.HandlerOption, ctx context.Context, token string) error {
		a := auth.New(opt)
		return a.RevokeToken(ctx, token)
	})
}

func Test_RevokeToken(t *testing.T) {
	testRevokeToken(t, func(opt auth.HandlerOption, ctx context.Context, token string) error {
		if err := auth.Extend("Test_RevokeToken", opt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = auth.SetDefault("Test_RevokeToken")
		return auth.RevokeToken(ctx, token)
	})
}

func TestUseDriver(t *testing.T) {
	driver := &MockDriver{user: &MockUser{ID: "fromUseDriver"}}
	auth.UseDriver(driver)

	v, err := auth.Validate(context.Background(), "token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !driver.validateCalled {
		t.Errorf("MockDriver.Validate() expected to be called")
	}

	u, ok := v.User.(*MockUser)
	if !ok {
		t.Fatalf("Validate() expected User to be of type *MockUser")
	}

	if u.ID != "fromUseDriver" {
		t.Errorf("Validate() user ID does not match")
	}
}

func TestUseUserProvider(t *testing.T) {
	userProvider := &MockUserProvider{user: &MockUser{ID: "fromUseUserProvider"}}
	auth.UseUserProvider(userProvider)

	u, err := auth.Authenticate(context.Background(), "creds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !userProvider.findByCredentialsCalled {
		t.Errorf("MockUserProvider.FindByCredentials() expected to be called")
	}

	user, ok := u.(*MockUser)
	if !ok {
		t.Fatalf("Authenticate() expected User to be of type *MockUser")
	}

	if user.ID != "fromUseUserProvider" {
		t.Errorf("Authenticate() user ID does not match")
	}
}

func TestUnsupportedMethods(t *testing.T) {
	t.Parallel()
	a := auth.New()
	if err := a.RegisterHandler("TestUnsupportedMethods", &MockHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := a.SetDefault("TestUnsupportedMethods"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ctx := context.Background()

	if _, err := a.RegisterUser(ctx, &MockUser{}); err != nil && !errors.Is(err, auth.ErrRegisterUserNotSupported) {
		t.Errorf("RegisterUser() expected error = %v, got %v", auth.ErrRegisterUserNotSupported, err)
	}

	if _, err := a.Login(ctx, &MockUser{}); err != nil && !errors.Is(err, auth.ErrLoginNotSupported) {
		t.Errorf("Login() expected error = %v, got %v", auth.ErrLoginNotSupported, err)
	}

	if err := a.Logout(ctx, "session"); err != nil && !errors.Is(err, auth.ErrLogoutNotSupported) {
		t.Errorf("Logout() expected error = %v, got %v", auth.ErrLogoutNotSupported, err)
	}

	if _, err := a.IssueToken(ctx, &MockUser{}); err != nil && !errors.Is(err, auth.ErrIssueTokenNotSupported) {
		t.Errorf("IssueToken() expected error = %v, got %v", auth.ErrIssueTokenNotSupported, err)
	}

	if _, err := a.RefreshToken(ctx, "refreshToken"); err != nil && !errors.Is(err, auth.ErrRefreshTokenNotSupported) {
		t.Errorf("RefreshToken() expected error = %v, got %v", auth.ErrRefreshTokenNotSupported, err)
	}

	if err := a.RevokeToken(ctx, "token"); err != nil && !errors.Is(err, auth.ErrRevokeTokenNotSupported) {
		t.Errorf("RevokeToken() expected error = %v, got %v", auth.ErrRevokeTokenNotSupported, err)
	}
}
