# Changelog

What changed for whoever runs `sermod`, calls its API, or builds on the
public packages, one section per release. A `v*` tag without a section
here is refused before it is pushed.

## Unreleased

### Added

- **`GET /v1/messaging/version` is public.** It answers the build's
  `version`, `commit` and `build_time` with no token, so a deployment
  behind an ingress that forwards only `/v1/messaging` shows which release
  it runs. The release smoke compares the served version with the tag.

## v0.2.0 - 2026-11-03

### Added

- **A person's history is kept as sealed records, so a new device reads
  it.** `POST /v1/messaging/conversations/{id}/backup` stores records
  that a person's devices sealed under their backup key, one for each
  message, and `GET` on the same path lists a person's own records of the
  conversation, oldest after a cursor or newest before it. A record the
  person's devices store twice is kept once. The server sees ciphertext,
  sizes and ids alone; one person's records hold at most 256 MiB, and the
  retention of the log never deletes them. Both calls are authorized as
  `backup.recovery`. Needs the database migration 000005.

## v0.1.1 - 2026-11-01

### Fixed

- **A waiting read gets a new message within a second on every replica.**
  A read held by a replica other than the one the message arrived at used
  to wait out its whole timeout, up to 30 seconds. With more than one
  replica running, about half of all messages arrived that late.

### Changed

- **Releases are built, signed and published by the shared release stages
  in latere-ai/ci.** The image signature and the signed `checksums.txt` now
  name those stages, run for this repository, and the release workflow
  checks every release it publishes the way an installer would.

## v0.1.0 - 2026-10-30

### Added

- **The first release of `sermod`,** the server for end-to-end
  encrypted conversations between people over MLS (RFC 9420). It serves
  the API of `api/openapi.yaml` under `/v1/messaging`: the directory of
  each person's devices with their vouches and revocations, the key
  packages a device offers, conversations and their ordered log of MLS
  messages with one commit per epoch, each group's latest group info,
  Welcomes, the recovery record, and whether a person is one of a
  conversation's people.
- Every commit is checked before it is kept: its signature against the
  sender's leaf, the leaf against a device of the person whose token
  sent it, and what it changes against the conversation's rules.
- A person is the `sub` of a token from any OpenID Connect issuer in
  `SERMO_OIDC_ISSUERS`, and every request is decided by the endpoint at
  `SERMO_AUTHORIZER_URL`, which must refuse the probe before the server
  starts. Without one, the server decides by its member policy.
- State is kept in Postgres with `SERMO_DATABASE_URL`, migrated at start
  over that direct endpoint, and served over `SERMO_DATABASE_POOL_URL`
  when it names a pooled one. Without a database it is kept in memory.
- A container image, `sermod`, for linux/amd64 and linux/arm64, which
  reports its release with `sermod -version` and at `/version`.
