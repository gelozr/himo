package hash_test

import (
	"errors"
	"testing"

	"github.com/gelozr/himo/hash"
)

func assertRoundTrip(t *testing.T, hasher hash.Hasher, password string) {
	hashed, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}

	ok, err := hasher.Check(password, hashed)
	if err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if !ok {
		t.Errorf("Check() expected true, got false")
	}

	ok, err = hasher.Check("wrong password", hashed)
	if err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if ok {
		t.Errorf("Check(wrong password) expected false, got true")
	}
}

func TestBcryptHasher_RoundTrip(t *testing.T) {
	hasher := hash.BcryptHasher{}
	password := "123456"

	assertRoundTrip(t, hasher, password)
}

func TestArgon2IDHasher_RoundTrip(t *testing.T) {
	hasher := hash.Argon2IDHasher{}
	password := "123456"

	assertRoundTrip(t, hasher, password)
}

type mockHasher struct {
	shouldFailHash  bool
	shouldFailCheck bool
	calledHash      bool
	calledCheck     bool
}

func (m *mockHasher) Hash(password string) (string, error) {
	m.calledHash = true

	if m.shouldFailHash {
		return "", errors.New("hash failed")
	}

	return "mock:" + password, nil
}

func (m *mockHasher) Check(password, hash string) (bool, error) {
	m.calledCheck = true

	if m.shouldFailCheck {
		return false, errors.New("check failed")
	}

	return "mock:"+password == hash, nil
}

func TestManager_HashCheckWithDefaultHasher(t *testing.T) {
	hasher := hash.New()
	password := "123456"

	assertRoundTrip(t, hasher, password)
}

func TestManager_MustHasher(t *testing.T) {
	h := hash.New()

	tests := []struct {
		name   string
		method hash.Method
		panics bool
	}{
		{name: "hasher found", method: hash.Bcrypt},
		{name: "panic on nil", method: "not found hasher", panics: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("MustHasher did not panic on nil hasher")
					}
				}()
			}

			hasher := h.MustHasher(tt.method)
			if _, ok := hasher.(hash.BcryptHasher); !ok {
				t.Errorf("expected hash.BcryptHasher, got %t", hasher)
			}
		})
	}
}

func TestManager_Hasher(t *testing.T) {
	h := hash.New()

	tests := []struct {
		name    string
		method  hash.Method
		wantErr bool
	}{
		{name: "hasher found", method: hash.Bcrypt},
		{name: "hasher not found", method: "not found hasher", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.Hasher(tt.method)

			if (err != nil) != tt.wantErr {
				t.Errorf("Hasher() expected error = %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestManager_HashCheckSelectedBuiltinHasher(t *testing.T) {
	hasher := hash.New()
	hashers := []hash.Method{hash.Bcrypt, hash.Argon2ID}
	password := "123456"

	for _, method := range hashers {
		t.Run(string(method), func(t *testing.T) {
			hashed, err := hasher.MustHasher(method).Hash(password)
			if err != nil {
				t.Fatalf("Hash() error = %v, want nil", err)
			}

			ok, err := hasher.MustHasher(method).Check(password, hashed)
			if err != nil {
				t.Fatalf("Check() error = %v, want nil", err)
			}
			if !ok {
				t.Errorf("Check() expected true, got false")
			}

			ok, err = hasher.MustHasher(method).Check("wrong password", hashed)
			if err != nil {
				t.Fatalf("Check() error = %v, want nil", err)
			}
			if ok {
				t.Errorf("Check(wrong password) expected false, got true")
			}
		})
	}
}

func TestManager_SetDefault(t *testing.T) {
	hasher := hash.New()

	tests := []struct {
		name    string
		method  hash.Method
		wantErr bool
	}{
		{name: "hasher found", method: hash.Method("mock")},
		{name: "hasher not found", method: hash.Method("not found hasher"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "hasher found" {
				if err := hasher.Extend(tt.method, &mockHasher{}); err != nil {
					t.Fatalf("SetDefault() error = %v, want nil", err)
				}
			}

			err := hasher.SetDefault(tt.method)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetDefault() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.wantErr && !errors.Is(err, hash.ErrHasherNotFound) {
				t.Errorf("SetDefault() expected error = %v, got %v", hash.ErrHasherNotFound, err)
			}
		})
	}
}

func TestManager_Hash(t *testing.T) {
	hasher := hash.New()
	password := "123456"

	tests := []struct {
		name         string
		expectedHash string
		hasher       *mockHasher
	}{
		{name: "hash success", expectedHash: "mock:123456", hasher: &mockHasher{calledHash: true}},
		{name: "hash failed", expectedHash: "", hasher: &mockHasher{calledHash: true, shouldFailHash: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := hasher.Extend("mock", tt.hasher); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			if err := hasher.SetDefault("mock"); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			s, err := hasher.Hash(password)
			if (err != nil) != tt.hasher.shouldFailHash {
				t.Errorf("Hash() expected error = %v, got %v", tt.hasher.shouldFailHash, err)
			}

			if !tt.hasher.calledHash {
				t.Errorf("mockHasher Hash() expected to be called")
			}

			if s != tt.expectedHash {
				t.Errorf("mockHasher Hash() expected to return %s, got %s", tt.expectedHash, s)
			}
		})
	}
}

func TestManager_Check(t *testing.T) {
	hasher := hash.New()

	tests := []struct {
		name          string
		password      string
		hashed        string
		expectedCheck bool
		hasher        *mockHasher
	}{
		{
			name:          "check success",
			password:      "123456",
			hashed:        "mock:123456",
			expectedCheck: true,
			hasher:        &mockHasher{calledCheck: true},
		},
		{
			name:          "check failed",
			password:      "wrong password",
			hashed:        "mock:123456",
			expectedCheck: false,
			hasher:        &mockHasher{calledCheck: true, shouldFailCheck: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := hasher.Extend("mock", tt.hasher); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			if err := hasher.SetDefault("mock"); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			ok, err := hasher.Check(tt.password, tt.hashed)
			if (err != nil) != tt.hasher.shouldFailCheck {
				t.Errorf("Check() expected error = %v, got %v", tt.hasher.shouldFailCheck, err)
			}

			if ok != tt.expectedCheck {
				t.Errorf("Check() expected to return %v, got %v", tt.expectedCheck, ok)
			}

			if !tt.hasher.calledCheck {
				t.Errorf("mockHasher Check() expected to be called")
			}
		})
	}
}

func TestHash_WithDefaultHasher(t *testing.T) {
	password := "123456"

	hashed, err := hash.Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v, want nil", err)
	}

	ok, err := hash.Check(password, hashed)
	if err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if !ok {
		t.Errorf("Check() expected true, got false")
	}

	ok, err = hash.Check("wrong password", hashed)
	if err != nil {
		t.Fatalf("Check() error = %v, want nil", err)
	}
	if ok {
		t.Errorf("Check(wrong password) expected false, got true")
	}
}

func TestMustHasher(t *testing.T) {
	tests := []struct {
		name   string
		method hash.Method
		panics bool
	}{
		{name: "hasher found", method: hash.Bcrypt},
		{name: "panic on nil", method: "not found hasher", panics: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("MustHasher did not panic on nil hasher")
					}
				}()
			}

			hasher := hash.MustHasher(tt.method)
			if _, ok := hasher.(hash.BcryptHasher); !ok {
				t.Errorf("expected hash.BcryptHasher, got %t", hasher)
			}
		})
	}
}

func TestLookupHasher(t *testing.T) {
	tests := []struct {
		name    string
		method  hash.Method
		wantErr bool
	}{
		{name: "hasher found", method: hash.Bcrypt},
		{name: "hasher not found", method: "not found hasher", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hash.LookupHasher(tt.method)

			if (err != nil) != tt.wantErr {
				t.Errorf("Hasher() expected error = %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestHashAndCheck_WithSelectedBuiltinHasher(t *testing.T) {
	hashers := []hash.Method{hash.Bcrypt, hash.Argon2ID}
	password := "123456"

	for _, method := range hashers {
		t.Run(string(method), func(t *testing.T) {
			hashed, err := hash.MustHasher(method).Hash(password)
			if err != nil {
				t.Fatalf("Hash() error = %v, want nil", err)
			}

			ok, err := hash.MustHasher(method).Check(password, hashed)
			if err != nil {
				t.Fatalf("Check() error = %v, want nil", err)
			}
			if !ok {
				t.Errorf("Check() expected true, got false")
			}

			ok, err = hash.MustHasher(method).Check("wrong password", hashed)
			if err != nil {
				t.Fatalf("Check() error = %v, want nil", err)
			}
			if ok {
				t.Errorf("Check(wrong password) expected false, got true")
			}
		})
	}
}

func TestSetDefault(t *testing.T) {
	tests := []struct {
		name    string
		method  hash.Method
		wantErr bool
	}{
		{name: "hasher found", method: hash.Method("mock")},
		{name: "hasher not found", method: hash.Method("not found hasher"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "hasher found" {
				if err := hash.Extend(tt.method, &mockHasher{}); err != nil {
					t.Fatalf("SetDefault() error = %v, want nil", err)
				}
			}

			err := hash.SetDefault(tt.method)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetDefault() expected error = %v, got %v", tt.wantErr, err)
			}

			if tt.wantErr && !errors.Is(err, hash.ErrHasherNotFound) {
				t.Errorf("SetDefault() expected error = %v, got %v", hash.ErrHasherNotFound, err)
			}
		})
	}
}

func TestHash(t *testing.T) {
	password := "123456"

	tests := []struct {
		name         string
		expectedHash string
		hasher       *mockHasher
	}{
		{name: "hash success", expectedHash: "mock:123456", hasher: &mockHasher{calledHash: true}},
		{name: "hash failed", expectedHash: "", hasher: &mockHasher{calledHash: true, shouldFailHash: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := hash.Extend("mock", tt.hasher); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			if err := hash.SetDefault("mock"); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			s, err := hash.Hash(password)
			if (err != nil) != tt.hasher.shouldFailHash {
				t.Errorf("Hash() expected error = %v, got %v", tt.hasher.shouldFailHash, err)
			}

			if !tt.hasher.calledHash {
				t.Errorf("mockHasher Hash() expected to be called")
			}

			if s != tt.expectedHash {
				t.Errorf("mockHasher Hash() expected to return %s, got %s", tt.expectedHash, s)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		hashed        string
		expectedCheck bool
		hasher        *mockHasher
	}{
		{
			name:          "check success",
			password:      "123456",
			hashed:        "mock:123456",
			expectedCheck: true,
			hasher:        &mockHasher{calledCheck: true},
		},
		{
			name:          "check failed",
			password:      "wrong password",
			hashed:        "mock:123456",
			expectedCheck: false,
			hasher:        &mockHasher{calledCheck: true, shouldFailCheck: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := hash.Extend("mock", tt.hasher); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			if err := hash.SetDefault("mock"); err != nil {
				t.Fatalf("SetDefault() error = %v, want nil", err)
			}

			ok, err := hash.Check(tt.password, tt.hashed)
			if (err != nil) != tt.hasher.shouldFailCheck {
				t.Errorf("Check() expected error = %v, got %v", tt.hasher.shouldFailCheck, err)
			}

			if ok != tt.expectedCheck {
				t.Errorf("Check() expected to return %v, got %v", tt.expectedCheck, ok)
			}

			if !tt.hasher.calledCheck {
				t.Errorf("mockHasher Check() expected to be called")
			}
		})
	}
}

func TestManager_CheckDetectsMethodFromHash(t *testing.T) {
	m := hash.New()
	bcryptHash, err := m.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}

	if err := m.SetDefault(hash.Argon2ID); err != nil {
		t.Fatal(err)
	}
	argonHash, err := m.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}

	for name, h := range map[string]string{"bcrypt": bcryptHash, "argon2id": argonHash} {
		if ok, err := m.Check("secret", h); err != nil || !ok {
			t.Errorf("%s hash with argon2id default: Check = %v, %v", name, ok, err)
		}
		if ok, err := m.Check("wrong", h); err != nil || ok {
			t.Errorf("%s hash, wrong password: Check = %v, %v", name, ok, err)
		}
	}
}
