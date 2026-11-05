# Install

What an installation of `sermod` that keeps its state needs: the image,
Postgres, the server's key, an issuer, and optionally an authorizer.
[Running it locally](local.md) is the same server with none of them.

## What you supply

| | Needed for | Set with |
|---|---|---|
| An OpenID Connect issuer whose tokens name the audience `sermo` | every request | `SERMO_OIDC_ISSUERS`, `SERMO_OIDC_AUDIENCE` |
| Postgres; the store's tests run against 17 | anything that should survive a restart | `SERMO_DATABASE_URL`, `SERMO_DATABASE_POOL_URL` |
| The server's Ed25519 key, in a file | a server with a database | `SERMO_SERVICE_KEY_FILE` |
| An authorizer and the bearer `sermod` sends it | deciding who may talk to whom; without one, the [member policy](authorizer.md#without-an-authorizer) | `SERMO_AUTHORIZER_URL`, `SERMO_AUTHORIZER_TOKEN_FILE` |
| A storage service for the files sent in conversations, which asks `sermod` whether a reader is one of a conversation's people | files, attachments and shared history | nothing in `sermod`; the service calls [`GET /conversations/{id}/people/{person}`](api.md#membership) |

[Configuration](configuration.md) describes every variable.

## The image

Every release publishes `ghcr.io/latere-ai/sermod:<tag>` for linux/amd64
and linux/arm64. It holds the one static binary on a distroless base,
runs as the user 65532, listens on 8080 and takes its configuration from
the environment:

```sh
podman run --rm ghcr.io/latere-ai/sermod:v0.2.0 -version
```

To build it yourself from a clone, `podman build --build-arg VERSION=<tag> -t sermod .`.

### Checking a release

The image is signed, and each release carries a bill of materials and
`checksums.txt`, signed, built by the shared release workflows in
[latere-ai/ci](https://github.com/latere-ai/ci) run for this repository.
With `TAG` the release's tag:

```sh
gh release download "$TAG" -R latere-ai/sermo -D sermo-release
cd sermo-release
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/latere-ai/ci/\.github/workflows/image-publish\.yml@' \
  --certificate-github-workflow-repository latere-ai/sermo checksums.txt
sha256sum -c checksums.txt

cosign verify "ghcr.io/latere-ai/sermod:$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/latere-ai/ci/\.github/workflows/image-build\.yml@' \
  --certificate-github-workflow-repository latere-ai/sermo
```

## Postgres

`sermod` applies its schema at start, over `SERMO_DATABASE_URL`, and then
serves. Give it a database of its own and a role that owns it.

- **Two addresses.** A migration holds a lock for its whole session, so
  it runs over a direct connection or a pooler in session mode. Serving
  can go through a pooler in transaction mode: name it in
  `SERMO_DATABASE_POOL_URL`, with `default_query_exec_mode=exec` when the
  pooler does not keep prepared statements.
- **Replicas.** Replicas share one database and hold nothing of their
  own, so any replica serves any request and a rollout replaces them one
  at a time. Replicas that start at once on an empty database wait for
  one another's migration. A read waiting for a message gets a new one
  within a second on whichever replica it waits on, and ends when its
  replica stops; the device reads again from another.
- **Connections.** Each replica holds at most 4 connections unless the
  URL its pool opens sets `pool_max_conns`. Leave room in the database's
  limit for one more connection per starting replica, which its
  migration opens and closes.
- **Retention.** Messages and welcomes older than `SERMO_RETENTION` are
  deleted by every replica every hour. Backup records are not.

A migration that fails halfway leaves the schema marked dirty, and the
next start refuses it rather than run over it: restore the database, or
repair the schema and clear the dirty flag the migrator keeps, then start
again. A binary older than the
schema it meets refuses to start, so an upgrade is rolled back by
restoring the database, not by starting the older image.

## The server's key

Every conversation's group names the server as its one external sender,
by the public half of this key, and the server signs the removals it
proposes for revoked devices with it. Make it once and keep it for the
life of the installation:

```sh
openssl rand -base64 32 > sermod-service-key
```

Mount the file read-only and name it in `SERMO_SERVICE_KEY_FILE`. Every
replica reads the same file. A conversation created under one key does
not accept removals proposed under another, so the key is backed up with
the database and never rotated.

## Probes

The probes are on the same listener as the API, and need no token:

| Path | Answers |
|---|---|
| `GET /livez` | `200` while the process runs. A failure means restart it |
| `GET /readyz` | `200` while the database answers and the server is not stopping. A failure means take it out of rotation; the body names the failing check |
| `GET /version` | the release, as `{"version", "commit", "build_time"}` |
| `GET /v1/messaging/version` | the same, under the API's prefix, for a proxy that forwards only `/v1/messaging` |

On a stop, `/readyz` fails at once, and `sermod` waits 3 seconds, ends
the reads waiting for messages, and closes within 30 seconds. Give the
process at least 35 seconds between the stop signal and a kill.

## The network

`sermod` serves plain HTTP; put TLS in front of it. Clients need
`/v1/messaging` and nothing else; the probes are for the orchestrator.
Besides the database, `sermod` makes outbound requests to the issuers
listed, to the authorizer, and to an OTLP endpoint when one is set, and
to nothing else.

## Upgrading

Read the release's section in the [changelog](../CHANGELOG.md) first. A
release that adds a migration says so, and the first replica that starts
applies it while the others wait for it.
