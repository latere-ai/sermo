# Contributing

Thanks for looking. This file is for people and agents changing Sermo.
People running it read the [README](README.md) and [`docs/`](docs/README.md);
the design, and the reasoning behind each decision, lives in
[`specs/`](specs/README.md).

## Getting set up

You need Go 1.27 or newer, `git`, and a container runtime that
Testcontainers can reach, Docker or Podman. Then:

```sh
make          # the full check
go build -o out/sermod ./cmd/sermod
make hooks    # once: the checks run before each commit and push
```

The check starts Postgres in a container for the store's suite, and
builds and starts the server's image. Where no container runtime
answers, that suite cannot run and the coverage floor fails for the
packages only it reaches: a skipped suite is never a passing check.
Under Podman on macOS, point Testcontainers at the machine's socket:

```sh
export DOCKER_HOST="unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')"
```

The helper that starts Postgres turns Testcontainers' reaper off under
Podman, where it cannot start, and removes the containers a killed test
left behind on its next run.

[Running it locally](docs/local.md) starts the server with an issuer to
try a change by hand.

## Sending a change

Fork the repository, work on a branch, and open a pull request. Keep one
logical change per commit, and write the subject as `scope: what
changed`, in lower case, for whoever reads the log.

If you are planning something large, open an issue first. A feature
starts as a spec in [`specs/`](specs/README.md) with acceptance criteria
that are testable sentences; small fixes need none. A change to a
behavior a spec describes updates the spec in the same change.

A change someone would notice updates what they read, in the same
change:

- the API: [`api/openapi.yaml`](api/openapi.yaml), which the tests hold
  to the routes, bodies, error codes and limits the server has, and
  [the API page](docs/api.md);
- a `SERMO_*` variable: [Configuration](docs/configuration.md);
- the authorizer's vocabulary or fields: the package `authorizer`, its
  spec, and [Writing an authorizer](docs/authorizer.md);
- anything someone running `sermod` or calling it would notice: a line
  under `## Unreleased` in [`CHANGELOG.md`](CHANGELOG.md), written for
  them. A `v*` tag without a section there is refused.

A maintainer cuts a release with `go tool lateregate release vX.Y.Z`,
from a commit whose checks passed.

## The bar

`make` runs the whole check, `go tool lateregate`: formatting, the
linter, modernization, known vulnerabilities, a build with no cgo, the
license notice, the identity and database declarations, the spec tree,
the image built and started as production runs it, and the suite under
the race detector with per-package coverage at 90% or more.
`go tool lateregate list` names each check, and `go tool lateregate
<name>` runs one.

A bug fix carries a test that fails without it.

## Rules that are not style

**What people write is never read here.** The server stores ciphertext
and the metadata it needs to deliver and decide. Nothing it logs,
returns, stores or keeps in a test fixture carries a message's plaintext
or a private key. A claim that one never leaves is proven by a test that
plants a canary and searches every output for it, and a new route joins
that test.

**MLS is not reimplemented here.** The server parses and checks what
devices send with `latere.ai/x/sdk-go/mls`, and applies the
conversation's rules and the directory with `latere.ai/x/sdk-go/messaging`,
the package every device applies, so a commit the server accepts is one
every honest device merges.

**Widening what the server can read is a change to the threat model.**
The assistant's member is the one place the server would hold a member's
keys. A change that widens when it can read is written in the specs and
in [`SECURITY.md`](SECURITY.md) first.

**This repository names no installation.** No hostname, token or
internal reference of anyone's appears outside an example, so the server
anyone runs from it carries no one else's defaults. Only
`internal/config` reads the environment.

**Every sentence has one reader.** An error has one code, one fixed
sentence for the person using an app in `message`, and one detail for a
developer. [The registers](https://github.com/latere-ai/pkg/blob/main/docs/writing/registers.md)
is the rule.

## Where things go

| Path | What lives there |
|---|---|
| `cmd/sermod/` | the server: configuration, the store, the authorizer and the probes wired together |
| `api/` | the HTTP contract, `openapi.yaml`. Public |
| `authorizer/` | the authorizer's vocabulary. Public |
| `internal/httpapi/` | the routes, their JSON, the token and the device a request speaks for, with the end-to-end tests |
| `internal/conv/` | what each route does: the directory, key packages, the log and its checks, backup records |
| `internal/access/` | token verification, the authorizer client and the member policy |
| `internal/store/` | the store's contract, the memory and Postgres stores, and the migrations |
| `internal/config/` | the `SERMO_*` settings, read once |
| `internal/apierr/` | the error codes and their sentences |
| `tools/smoke/` | the check a release runs against a live server |
| `specs/` | one spec per component, indexed in [`specs/README.md`](specs/README.md) |

The public packages, `api` and `authorizer`, change additively within a
major version of the module: a change keeps every existing caller
compiling, or the changelog names the break.

## Reporting a vulnerability

Do not open an issue. [`SECURITY.md`](SECURITY.md) says where to send it.
