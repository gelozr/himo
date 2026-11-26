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
