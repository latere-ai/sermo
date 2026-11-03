---
title: "Identity and authorization: a token from any OpenID Connect issuer, the device a request speaks for, and one question to the authorizer per request, with the conversation's facts"
status: drafted
track: core
depends_on:
  - specs/001-architecture.md
  - specs/002-api.md
affects: [authorizer/, internal/access/, internal/httpapi/, cmd/sermod/]
effort: medium
created: 2026-10-29
updated: 2026-10-29
author: changkun
---

# Identity and authorization

## Overview

Sermo verifies who sends a request and asks an authorizer whether they
may. It decides nothing about people itself: who may talk to whom, the
limits on new conversations, blocks between people and
an account's standing are the authorizer's. What Sermo does decide is
what MLS and the conversation's rules decide, which every device decides
too: a commit that breaks the rules is refused before the authorizer is
asked.

## Design

### Identity

A token is verified against the issuer's keys, with Sermo's audience.
The authorizer's subject is the issuer and the sub joined, as
`latere.ai/x/pkg/authz` renders it. A person is the sub alone, which
every device's credential names (`user:<sub>/device:<id>`): the
directory, the conversations' people and the recovery records are keyed
by it. Every issuer one server lists therefore issues subs from one
namespace, such as one identity provider under more than one address;
issuers whose subs can collide are two servers. A
device names itself in `Sermo-Device`; Sermo checks the device is one
of the subject's that is not revoked. A caller for the assistant, such
as an agent's session, presents its own token, and Sermo passes its
claims to the authorizer verbatim.

### The question

Sermo asks `POST <authorizer>` with the envelope of
`latere.ai/x/pkg/authz`: the subject, the claims, one action, and the
resource with its kind, its id and the fields below, flat. A field Sermo
does not know for a request is absent. The allow may carry a time to
live, which the client caches for, and nothing else is read from it.

The vocabulary, which the package `authorizer` declares once:

| Kind | Action | Fields |
|---|---|---|
| `Conversation` | `conversation.create` | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.read` | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.list` | `person` |
| `Conversation` | `conversation.send` | `id`, `conversation_kind`, `people`, `owners`, `level`, `size` |
| `Conversation` | `conversation.commit` | `id`, `conversation_kind`, `people`, `owners`, `level`, `changes`, `add_people`, `remove_people`, `new_owners`, `new_level` |
| `Conversation` | `conversation.leave` | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.membership` | `id`, `conversation_kind`, `people`, `owners`, `level`, `person` |
| `Conversation` | `conversation.assistant_read` | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.assistant_post` | `id`, `conversation_kind`, `people`, `owners`, `level`, `asked_by` |
| `Device` | `device.register` | `person`, `root` |
| `Device` | `device.vouch` | `id`, `person` |
| `Device` | `device.list` | `person` |
| `Device` | `device.delete` | `id`, `person` |
| `KeyPackage` | `key_package.publish` | `person`, `device` |
| `KeyPackage` | `key_package.claim` | `person`, `conversation` |
| `Backup` | `backup.recovery` | `person` |

- `people` and `owners` are the conversation's, as the epoch the request
  comes to holds them, and `level` is `off`, `reads_along` or
  `takes_part`.
- `changes` lists what a commit changes, of `add_people`,
  `remove_people`, `owners`, `level` and `devices`; `add_people` and
  `remove_people` are the people it adds and removes, `new_owners` and
  `new_level` the owners and level it leaves. A proposal is asked as
  `conversation.leave` when it removes its sender's own leaves, and as
  `conversation.commit` otherwise.
- `size` is a sent message's length in bytes.
- `person` is whose record, key package or recovery record it is, and
  on `conversation.membership` the person asked about; on
  `key_package.claim`, the person claimed for, with the `conversation`
  the claim is for. `root` says a device registers as a new root, with
  no voucher among the person's records.
- `backup.recovery` is also asked by storing and listing the backup
  records of a conversation, with the caller as `person`.
- `asked_by` is the person an answer posted as the assistant answers.

A deny is answered `403 forbidden`, with the authorizer's reason in the
error's `detail`. An authorizer that does not answer fails the request
closed with `503 authorizer_unavailable`. `sermod` starts only once the
authorizer refuses the probe every authorizer refuses; without
`SERMO_AUTHORIZER_URL` it decides in process by the member policy: a
person acts on their own records and on conversations they are in.

## Acceptance criteria

1. The package `authorizer` declares exactly the table above, which a
   test reads from this file.
2. Every route of the API asks the action the API's table names, with
   the fields above, and a test drives each.
3. A device that is not the subject's, or is revoked, is refused before
   the authorizer is asked.
4. An authorizer that times out fails the request with
   `503 authorizer_unavailable` and changes nothing.
