---
title: "Backup records: each person's history, one sealed record per message, kept as ciphertext beside the log and read back by a new device"
status: drafted
track: core
depends_on:
  - specs/001-architecture.md
  - specs/002-api.md
  - specs/003-identity-and-authorization.md
affects: [internal/conv/, internal/httpapi/, internal/store/, api/openapi.yaml]
effort: medium
created: 2026-11-03
updated: 2026-11-03
author: changkun
---

# Backup records

## Overview

A device that joins a conversation reads only the messages sent after it
joined, since MLS gives a new member no earlier epoch's keys. A person's
history therefore needs a path of its own. Every message a device of the
person sends or reads is sealed as one record under the person's backup
key, the key their recovery key already unwraps, and stored here as
ciphertext. A device that holds the backup key reads the records of each
conversation and has the history.

## Design

Sermo keeps the records, where the first draft of the architecture left
backup records to a storage service. The reasons: a record is small and
is read by its owner alone, while that service decides a read by whether
the reader is one of a conversation's people, which is the wrong question
for a person's own backup, and an account's records need an order a
device can page by, which this server assigns when it stores them. The
decision is recorded in the architecture's fifth invariant.

- A record has an `id`, a keyed hash of the message the person's devices
  derive from the backup key, so two devices store one message's record
  once and the server cannot tell which message a record is. A record is
  stored under the person, the conversation and the `id`; a record whose
  key is stored already is left as it was.
- The server gives each stored record a `cursor`, its place in the order
  stored, which a reader pages by, oldest after a cursor or newest
  before it.
- The calls are authorized as `backup.recovery` with the caller as
  `person`: the records are the person's own, as the recovery record is.
  The caller must be, or have been, one of the conversation's people, and
  speaks for a device that stands. A person's records of a conversation
  they left stay theirs.
- One constant bounds a sealed record, one the records of a call and one
  the bytes a person's records hold in all. A write that would pass the
  last stores nothing and is answered `too_large`.
- The retention sweep deletes messages and welcomes, never records.

## Acceptance criteria

1. Records stored by two devices of a person under one `id` are listed
   once, as the first stored them; another person's records of the same
   conversation, with the same `id`, are theirs alone.
2. A page lists records oldest or newest first by `cursor`, and a reader
   that follows `next` reads each record once.
3. A caller who never was one of the conversation's people, or whose
   device does not stand, or whom the authorizer refuses, reads and stores
   nothing.
4. The limits of a record, a call and a person are the documented
   constants, and a write past the person's limit stores none of its
   records.
5. The retention sweep leaves every record, and a canary planted in a
   record is found in no log line.
