# Embedding Sermo in a Go program

`latere.ai/x/sermo/server` runs Sermo inside your own process. Use it when
the messaging API should sit behind your own router, listener and
authorizer instead of in a separate `sermod`. `sermod` is built on the same
package, so an embedded server behaves as `sermod` does.

```go
s, err := server.New(ctx, server.Options{
	OIDCIssuers: []string{"https://issuer.example.com"},
	// DatabaseURL and ServiceKey keep state across restarts; without
	// them the server keeps its state in memory.
})
if err != nil {
	return err
}
defer s.Close()
go s.Sweep(ctx, time.Hour)

mux.Handle(server.Prefix+"/", s.Handler())
```

## What you get and what stays yours

`Handler` is the API under `server.Prefix` (`/v1/messaging`) and nothing
else. It verifies the caller's token against `OIDCIssuers` and
`OIDCAudiences`, which default to the audience `sermo`. The listener, TLS,
health probes, telemetry and graceful shutdown stay with your program.
`Ping` answers whether the store is reachable, for your readiness probe.

## The authorizer

`Options.Authorizer` is a
[`latere.ai/x/pkg/authz`](https://pkg.go.dev/latere.ai/x/pkg/authz)
`Authorizer` that decides who may reach whom, in the vocabulary of
[Writing an authorizer](authorizer.md). Leave it nil for the member
policy, which needs no service. Requests fail closed when the authorizer
cannot answer.

## State and keys

With `DatabaseURL` set the server keeps its state in Postgres, runs its
migrations in `New`, and needs a `ServiceKey`, an Ed25519 private key that
stays the same across restarts: every stored group names it as its
external sender, so `New` refuses a database with no key. Without a
database the server uses memory and makes a key itself, and keeps nothing
across a restart. `DatabasePoolURL` names a transaction pooler for the
server's queries while `DatabaseURL` runs the migrations.

Call `Close` after the handler has stopped serving and `Sweep` has
returned. `Sweep` deletes messages older than `Retention` (30 days by
default) at start and then every interval until its context is done.
