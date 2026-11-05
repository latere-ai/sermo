## What this changes

<!-- What is different after this for whoever runs sermod, builds a client for it, or writes its authorizer. -->

## Why

<!-- The problem it solves. Link the issue if there is one. -->

## Checklist

- [ ] `make` passes locally.
- [ ] A bug fix carries a test that fails without it.
- [ ] Nothing logged, returned, stored or kept in a fixture carries a
      message's plaintext or a private key, and a new route is exercised
      by the test that searches every output for a planted one.
- [ ] MLS and the conversation's rules come from
      `latere.ai/x/sdk-go/mls` and `messaging`, not code of this
      repository's own.
- [ ] Nothing widens what the server can read, or the threat model in
      `SECURITY.md` says so first.
- [ ] A change to the API, a `SERMO_*` variable, or the authorizer's
      vocabulary is in its spec, in `docs/`, and in `api/openapi.yaml`
      where it applies.
- [ ] A change someone running or calling `sermod` would notice has a
      line under `## Unreleased` in `CHANGELOG.md`.
