# Changelog

What changed for whoever runs `sermod`, calls its API, or builds on the
public packages, one section per release. A `v*` tag without a section
here is refused before it is pushed.

## Unreleased

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
