package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gelozr/himo/auth"
	"github.com/gelozr/himo/event"
)

func TestRoutes_RegisterLoginMeLogout(t *testing.T) {
	users := auth.New(auth.HandlerOption{
		Driver:       auth.NewJWTDriver([]byte(strings.Repeat("k", 32))),
		UserProvider: auth.NewMemoryUserProvider(),
	})
	srv := httptest.NewServer(routes(users, event.NewBus[userRegistered](), slog.New(slog.DiscardHandler)))
	defer srv.Close()

	// do sends a request, checks the status and returns the response body.
	do := func(method, path, token, body string, want int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "bearer "+token) // lowercase: the scheme is case-insensitive
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d, want %d", method, path, resp.StatusCode, want)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	account := `{"email":"a@example.com","password":"correct horse"}`
	do("POST", "/register", "", account+" {}", http.StatusBadRequest)
	do("POST", "/register", "", account+" invalid", http.StatusBadRequest)
	do("POST", "/register", "", account+" \n", http.StatusCreated)
	do("POST", "/register", "", account, http.StatusConflict)
	do("POST", "/register", "", `{"email":"b@example.com","password":"short"}`, http.StatusBadRequest)
	for _, body := range []string{
		`{"email":"Desk <\"front desk\"@example.com>","password":"correct horse"}`,
		`{"email":"<\"front desk\"@example.com>","password":"correct horse"}`,
		`{"email":"\"front desk\"@example.com (Desk)","password":"correct horse"}`,
		`{"email":"\"front\ndesk\"@example.com","password":"correct horse"}`,
	} {
		do("POST", "/register", "", body, http.StatusBadRequest)
	}
	quotedAccount := `{"email":"\"front desk\"@example.com","password":"correct horse"}`
	do("POST", "/register", "", quotedAccount, http.StatusCreated)
	do("POST", "/login", "", quotedAccount, http.StatusOK)
	do("POST", "/login", "", `{"email":"a@example.com","password":"wrong password"}`, http.StatusUnauthorized)

	var login struct{ Token string }
	if err := json.Unmarshal(do("POST", "/login", "", account, http.StatusOK), &login); err != nil {
		t.Fatal(err)
	}

	do("GET", "/me", "", "", http.StatusUnauthorized)
	do("GET", "/me", login.Token, "", http.StatusOK)

	var refreshed struct{ Token string }
	if err := json.Unmarshal(do("POST", "/refresh", login.Token, "", http.StatusOK), &refreshed); err != nil {
		t.Fatal(err)
	}
	do("GET", "/me", login.Token, "", http.StatusUnauthorized) // refresh revokes the old token
	do("GET", "/me", refreshed.Token, "", http.StatusOK)

	do("POST", "/logout", refreshed.Token, "", http.StatusNoContent)
	do("GET", "/me", refreshed.Token, "", http.StatusUnauthorized)
}

func TestBearerTokenAllowsMultipleSpaces(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/me", nil)
	r.Header.Set("Authorization", "Bearer   example.token")
	if token, ok := bearerToken(r); token != "example.token" || !ok {
		t.Fatalf("bearerToken() = %q, %t, want %q, true", token, ok, "example.token")
	}
}

func TestDecodeRejectsOversizeBody(t *testing.T) {
	for name, body := range map[string]string{
		"JSON value":          `{"email":"` + strings.Repeat("a", 1<<20) + `"}`,
		"trailing whitespace": `{}` + strings.Repeat(" ", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
			w := httptest.NewRecorder()
			if decode(w, r, new(credentials)) || w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("decode returned status %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}
}

func TestMailFrom(t *testing.T) {
	for _, tc := range []struct {
		value, name, address string
	}{
		{`noreply@example.com`, "himo", `noreply@example.com`},
		{`Welcome Team <noreply@example.com>`, "Welcome Team", `noreply@example.com`},
		{`"no  reply"@example.com`, "himo", `"no  reply"@example.com`},
		{`"Welcome <Team>" <"desk@\"room\" >"@example.com>`, "Welcome <Team>", `"desk@\"room\" >"@example.com`},
		{`"Welcome" <"@desk"@example.com>`, "Welcome", `"@desk"@example.com`},
		{`Welcome <""@example.com>`, "Welcome", `""@example.com`},
		{`noreply@[IPv6:2001:db8::1]`, "himo", `noreply@[IPv6:2001:db8::1]`},
		{`"Welcome @[IPv6:2001:db8::1]" <"desk@room"@[ipv6:2001:db8::1]>`, "Welcome @[IPv6:2001:db8::1]", `"desk@room"@[ipv6:2001:db8::1]`},
		{`quoted-local@example.com ("other"@example.net)`, `"other"@example.net`, "quoted-local@example.com"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("MAIL_FROM", tc.value)
			from, err := mailFrom()
			if err != nil {
				t.Fatal(err)
			}
			if from.Name != tc.name || from.Address != tc.address {
				t.Errorf("MAIL_FROM = %#v, want name %q and address %q", from, tc.name, tc.address)
			}
		})
	}
}

func TestMailFromRejectsInvalidQuotedLocalPart(t *testing.T) {
	t.Setenv("MAIL_FROM", "Welcome <\"tab\tinside\"@example.com>")
	if _, err := mailFrom(); err == nil {
		t.Fatal("accepted a tab in quoted local part")
	}
}

func TestMailFromRejectsInvalidIPv6Literal(t *testing.T) {
	t.Setenv("MAIL_FROM", `Welcome <noreply@[IPv6:192.0.2.1]>`)
	if _, err := mailFrom(); err == nil {
		t.Fatal("accepted an IPv4 address with an IPv6 tag")
	}
}

func TestWelcomeMailRejectsOutOfRangePort(t *testing.T) {
	t.Setenv("MAIL_HOST", "localhost")
	t.Setenv("MAIL_FROM", "noreply@example.com")

	for _, port := range []string{"-1", "0", "65536"} {
		t.Run(port, func(t *testing.T) {
			t.Setenv("MAIL_PORT", port)
			_, err := welcomeMail()
			if err == nil || !strings.HasPrefix(err.Error(), "MAIL_PORT:") {
				t.Fatalf("welcomeMail() error = %v, want MAIL_PORT error", err)
			}
		})
	}
}
