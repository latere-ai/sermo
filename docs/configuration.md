# Configuration

Every environment variable `sermod` reads, its default, and what it does.
`sermod` reads its configuration once, when it starts, and takes no
arguments but `-version`. A value that is missing or does not parse stops
the start with one message that names every problem at once, each by its
variable and never by its value, since a variable may hold a secret. A
variable set to the empty string is unset, and surrounding spaces are
dropped.

Durations are written the way Go writes them: `30s`, `5m`, `720h`. A size
is a whole number of bytes. A list is comma separated, and an empty entry
is dropped.

## Address

| Variable | Default | What it is |
|---|---|---|
| `SERMO_ADDR` | `:8080` | the address `sermod` listens on, for the API under `/v1/messaging` and the probes beside it |

## Store

| Variable | Default | What it is |
|---|---|---|
| `SERMO_DATABASE_URL` | unset: the memory store | the direct address of the Postgres database, as a `postgres://` URL. The migrations run over it at start. Unset, `sermod` keeps everything in the process, says `store=memory` on its first line, and loses it all on exit |
| `SERMO_DATABASE_POOL_URL` | unset: serving uses `SERMO_DATABASE_URL` | the address the server's connection pool opens once the migrations have run, a pooler where you run one. Needs `SERMO_DATABASE_URL`, since a migration holds a lock for its whole session, which a pooler in transaction mode does not keep. For a pooler that does not keep prepared statements, add `default_query_exec_mode=exec` to this URL |
| `SERMO_SERVICE_KEY_FILE` | required with a database | the path of a file holding the server's Ed25519 key as its 32-byte seed in standard base64, read once at start. Every conversation's group names the key's public half as its external sender, the one party besides its members that may propose a change: the removal of a revoked device. So the key is the same on every replica and is never replaced; a conversation created under one key refuses the removals another proposes. Without a database and without this variable, a new key is made at start |

The pool holds at most 4 connections per replica and returns one idle for
a minute. `pool_max_conns` and `pool_max_conn_idle_time` in the URL the
pool opens set them instead.

## Identity

| Variable | Default | What it is |
|---|---|---|
| `SERMO_OIDC_ISSUERS` | required | the OpenID Connect issuers whose tokens are accepted, each an `http` or `https` URL. At start `sermod` reads each one's discovery document and key set for up to 10 seconds; one that does not answer is named in the log, the server starts, and its keys are read when its first token arrives. A person is a token's `sub` alone, so every issuer listed must issue subjects from one namespace, such as one identity provider under more than one address |
| `SERMO_OIDC_AUDIENCE` | `sermo` | the audiences a token may name, one or more |

## Authorization

| Variable | Default | What it is |
|---|---|---|
| `SERMO_AUTHORIZER_URL` | unset: the member policy | the endpoint asked whether a caller may do what a request asks, an `http` or `https` URL. At start it is sent a question it must refuse, and `sermod` does not start if it allows it or does not answer. [Writing an authorizer](authorizer.md) is the contract, and the member policy the default |
| `SERMO_AUTHORIZER_TOKEN_FILE` | required with the URL | the path of a file holding the bearer `sermod` sends the authorizer, read once at start. A file that is missing, unreadable or empty stops the start. It is refused without the URL |

## The assistant's member

| Variable | Default | What it is |
|---|---|---|
| `SERMO_INSTALLATION_KEY` | unset: no assistant | the Ed25519 public key, in standard base64, whose signature attests the assistant's member of a conversation. Unset, a commit that adds a member the key would attest is refused. The routes through which a caller reads and posts as that member are not served yet ([Status](../README.md#status)) |

## Limits

| Variable | Default | What it is |
|---|---|---|
| `SERMO_MAX_REQUEST_BYTES` | `8388608` (8 MiB) | the largest request body. A commit with the group info and ratchet tree of a large group is the largest request, so the value is at least `1048576` (1 MiB). Past it, `413 too_large` |
| `SERMO_RETENTION` | `720h` (30 days) | how long a conversation's messages and welcomes are kept for devices that have not fetched them. Every replica deletes older ones at start and then every hour, or every half of the retention when that is shorter. A person's backup records are never deleted by it |

The limits the API holds itself, such as the key packages one call
publishes or the bytes one person's backup records hold, are in
[the API](api.md#limits).

## Telemetry

`sermod` writes its log as one JSON object per line to standard error, at
the info level. It reads the standard OpenTelemetry variables: with
`OTEL_EXPORTER_OTLP_ENDPOINT` set, it also sends its logs, traces and
metrics there over OTLP, and with `OTEL_SDK_DISABLED=true` it sends
nothing. A request's log line carries its route, its error code and the
error's detail, never its body or its token.

## Starting and stopping

`sermod -version` prints the release and exits. `sermod` exits 0 after a
clean stop, 1 when it cannot start or serve, and 2 on a usage error.

On `SIGTERM` or `SIGINT`, `/readyz` answers not ready at once, `sermod`
waits 3 seconds for a load balancer to notice, ends every read that is
waiting for a message, and closes within 30 seconds.
