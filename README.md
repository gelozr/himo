# HIMO

A lightweight, pluggable Go toolkit offering core backend services.

```sh
go get github.com/gelozr/himo
```

Requires Go 1.26.

| Package | What it does |
|---------|--------------|
| `auth`  | Authentication handlers built from a user provider and a driver (JWT or session). A `Manager` holds named handlers; package-level functions use a default one. |
| `hash`  | Password hashing with bcrypt (default) or argon2id. `Check` detects the algorithm from the hash, so changing the default keeps old hashes valid. |
| `event` | Typed in-process event buses, and a `Broker` that routes events to a bus by type. |
| `log`   | Builds a configured `*slog.Logger` (text or JSON, stdout or file). |
| `mail`  | Sends MIME mail over SMTP; `Manager` routes to named mailers. |

## Example server

`main.go` is a small HTTP API built from these packages. Configuration is listed in its package comment.

```sh
JWT_KEY=$(openssl rand -hex 32) go run .
curl -X POST localhost:8080/register -d '{"email":"a@example.com","password":"correct horse"}'
curl -X POST localhost:8080/login    -d '{"email":"a@example.com","password":"correct horse"}'   # {"token":"..."}
curl localhost:8080/me -H "Authorization: Bearer <token>"
```

Routes: `POST /register`, `POST /login`, `POST /refresh`, `POST /logout`, `GET /me`.

## Library example

```go
ctx := context.Background()

// The default handler uses JWTs signed with a random per-process key.
// For real use, pass your own driver: auth.New(auth.HandlerOption{Driver: auth.NewJWTDriver(key), UserProvider: ...})
user, _ := auth.RegisterUser(ctx, &auth.User{Email: "a@example.com", Password: "secret"})
token, _ := auth.IssueToken(ctx, user)
verified, _ := auth.Validate(ctx, token)

logger, closeLog, _ := log.New(log.Config{LogFormat: "json"})
defer closeLog()
logger.Info("validated", "user", verified.User)
```

`MemoryUserProvider` and `MemorySessionDriver` keep state in memory and are meant for tests and demos.
