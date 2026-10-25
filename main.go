// Command himo is a small HTTP API built from the himo packages: register,
// log in with email and password, and call protected routes with a bearer JWT.
//
// Users are kept in memory, so they are lost on restart. Swap
// auth.NewMemoryUserProvider for a provider backed by your database.
//
// Configuration (environment variables):
//
//	JWT_KEY     required, at least 32 bytes
//	ADDR        listen address (default :8080)
//	LOG_LEVEL   debug, info, warn, error (default info)
//	LOG_FORMAT  text or json (default text)
//	MAIL_HOST   when set, a welcome email is sent on registration
//	MAIL_PORT   default 587
//	MAIL_USER, MAIL_PASS, MAIL_FROM
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gelozr/himo/auth"
	"github.com/gelozr/himo/event"
	"github.com/gelozr/himo/log"
	"github.com/gelozr/himo/mail"
)

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (c credentials) validate() error {
	if addr, err := netmail.ParseAddress(c.Email); err != nil || addr.Address != c.Email {
		return errors.New("invalid email")
	}
	// bcrypt only uses the first 72 bytes and rejects longer input.
	if len(c.Password) < 8 || len(c.Password) > 72 {
		return errors.New("password must be 8 to 72 bytes")
	}
	return nil
}

type userRegistered struct {
	ID    string
	Email string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	logger, closeLog, err := log.New(log.Config{
		LogLevel:  os.Getenv("LOG_LEVEL"),
		LogFormat: os.Getenv("LOG_FORMAT"),
	})
	if err != nil {
		return err
	}
	defer func() { _ = closeLog() }()
	// Async event handlers log through slog's default logger.
	slog.SetDefault(logger)

	key := os.Getenv("JWT_KEY")
	if len(key) < 32 {
		return errors.New("JWT_KEY must be set and at least 32 bytes long")
	}

	users := auth.New(auth.HandlerOption{
		Driver:       auth.NewJWTDriver([]byte(key)),
		UserProvider: auth.NewMemoryUserProvider(),
	})

	registered := event.NewBus[userRegistered]()
	registered.SubscribeAsync(func(ctx context.Context, e userRegistered) error {
		logger.InfoContext(ctx, "user registered", "id", e.ID)
		return nil
	})
	if os.Getenv("MAIL_HOST") != "" {
		send, err := welcomeMail()
		if err != nil {
			return err
		}
		registered.SubscribeAsync(send)
	}

	srv := &http.Server{
		Addr:              cmp.Or(os.Getenv("ADDR"), ":8080"),
		Handler:           routes(users, registered, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("listening", "addr", srv.Addr)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	// One budget for both steps: under the 30s default grace period of Docker and Kubernetes,
	// and longer than ReadTimeout so a slow /register finishes publishing before the wait.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)

	waited := make(chan struct{})
	go func() {
		registered.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-shutdownCtx.Done():
		logger.Warn("shutdown timed out with welcome emails still sending")
	}
	return err
}

func routes(users *auth.Manager, registered *event.Bus[userRegistered], logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		var c credentials
		if !decode(w, r, &c) {
			return
		}
		if err := c.validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		u, err := users.RegisterUser(r.Context(), &auth.User{Email: c.Email, Password: c.Password})
		if errors.Is(err, auth.ErrUserAlreadyExists) {
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		if err != nil {
			serverError(w, r, logger, err)
			return
		}

		user := u.(*auth.User)
		if err := registered.Publish(r.Context(), userRegistered{ID: user.ID, Email: user.Email}); err != nil {
			logger.ErrorContext(r.Context(), "publish user registered", "err", err)
		}
		writeJSON(w, http.StatusCreated, map[string]string{"id": user.ID})
	})

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var c credentials
		if !decode(w, r, &c) {
			return
		}

		user, err := users.Authenticate(r.Context(), auth.PasswordCredentials{Email: c.Email, Password: c.Password})
		if err != nil {
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}

		token, err := users.IssueToken(r.Context(), user)
		if err != nil {
			serverError(w, r, logger, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": token})
	})

	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		old, ok := bearerToken(r)
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		token, err := users.RefreshToken(r.Context(), old)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": token})
	})

	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		if err := users.RevokeToken(r.Context(), token); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("GET /me", requireUser(users, func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromCtx(r.Context()).(*auth.User)
		writeJSON(w, http.StatusOK, map[string]string{"id": user.ID})
	}))

	return mux
}

// requireUser rejects requests without a valid bearer token and stores the user in the request context.
func requireUser(users *auth.Manager, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		verified, err := users.Validate(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(auth.WithUserCtx(r.Context(), verified.User)))
	})
}

func welcomeMail() (event.Handler[userRegistered], error) {
	port, err := strconv.Atoi(cmp.Or(os.Getenv("MAIL_PORT"), "587"))
	if err != nil {
		return nil, fmt.Errorf("MAIL_PORT: %w", err)
	}

	mailer := mail.NewManager(mail.Config{
		MailHost: os.Getenv("MAIL_HOST"),
		MailPort: port,
		MailUser: os.Getenv("MAIL_USER"),
		MailPass: os.Getenv("MAIL_PASS"),
	})
	// MAIL_FROM may be "noreply@example.com" or "Name <noreply@example.com>".
	parsed, err := netmail.ParseAddress(os.Getenv("MAIL_FROM"))
	if err != nil {
		return nil, fmt.Errorf("MAIL_FROM: %w", err)
	}
	from := mail.Address{Name: cmp.Or(parsed.Name, "himo"), Address: parsed.Address}

	return func(ctx context.Context, e userRegistered) error {
		// Async handlers get a context without cancellation, so bound the send here.
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		return mailer.Send(ctx, &mail.Message{
			From:    from,
			To:      []mail.Address{{Address: e.Email}},
			Subject: "Welcome",
			Text:    "Your account is ready.",
		})
	}, nil
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func serverError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	logger.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// bearerToken reads "Authorization: Bearer <token>". The scheme is case-insensitive (RFC 7235).
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
