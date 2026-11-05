# Security

What an installation of Sermo guarantees the people who use it, what the
server can see, and what whoever runs it must keep safe. The commitments,
each with the test that holds it, what is not defended, and how to
report a vulnerability are in [`SECURITY.md`](../SECURITY.md).

## What it guarantees

- **The server cannot read what people write.** Devices encrypt every
  message for the members of its conversation with MLS (RFC 9420), and
  the server holds no key that opens it: not a device's keys, not an
  epoch's secrets, not a person's recovery key or backup key. What it
  keeps of a message, a Welcome, a backup record or a backup key left
  for a new device is the ciphertext a device sent.
- **Every change to a conversation is checked where it can be.** A
  commit that adds or removes a person, changes the owners or changes
  the assistant's level is signed by the member who made it, checked by
  the server against the conversation's rules before it is kept, and
  checked again by every device before it is merged. The server and the
  devices apply the same rules from the same package.
- **A device belongs to its person.** The server lists a device only
  when the person's own keys vouch for it, and a person removes one with
  a revocation their own keys sign; the server can neither remove a
  device on its own nor undo a removal. When a device is revoked, the
  server proposes its removal from every conversation of its person's.
- **Nothing happens without a decision.** Every request carries a token
  from an issuer the operator listed, and the authorizer decides it
  before the server reads or acts. A request the authorizer cannot
  decide is refused.

The server cannot check what needs an epoch's secrets, and it delivers
what it chooses to deliver. [What is not defended](../SECURITY.md#what-is-not-defended)
says what that leaves open.

## What the server sees

End-to-end encryption hides what people write, not the shape of who
talks to whom. The server keeps, and an operator or a reader of its
database can learn:

| What | Kept |
|---|---|
| People | each person as their token's subject, and the subjects of every conversation's people and owners. No name, handle or address |
| Devices | every device of every person, its public keys, which device vouched for it, and its revocation |
| Conversations | each conversation's kind, its people in the order they joined, its owners, how far the assistant takes part, its epoch, and when it was created and last written to |
| Changes | every proposal and commit, which MLS sends unencrypted so the server can check it: who added or removed whom, and who changed the owners or the level |
| Messages | for each message: the conversation, the epoch, the person and the device whose token sent it, when, and its size, padded on the device to one of 256 bytes, 1, 4, 16, 64 or 256 KiB |
| Backup records | how many records a person stores for each conversation, their sizes, and when |
| Requests | not kept. Each question to the authorizer carries the caller's subject and claims, address and user agent, and the log keeps each refused request's route, error code and detail, never a body or a token |

Messages and Welcomes are deleted after the retention, 30 days by
default ([`SERMO_RETENTION`](configuration.md#limits)). Nothing else is
deleted: revoked records stay, so the vouches under them still verify.

## What an operator keeps safe

| What | Why |
|---|---|
| The server's key, in `SERMO_SERVICE_KEY_FILE` | every conversation's group names it as the one party besides its members that may propose a change. Whoever holds it can propose the removal of any device, which every device refuses unless the device's person revoked it. Lose it, and conversations cannot remove revoked devices through the server again |
| The database, and its backups | it holds everything in [What the server sees](#what-the-server-sees). A copy of it is that metadata, and no message |
| The authorizer's bearer, in `SERMO_AUTHORIZER_TOKEN_FILE`, and the authorizer itself | the authorizer decides who reaches whom. It cannot make the server read a message |
| The issuers listed in `SERMO_OIDC_ISSUERS` | an issuer that signs a token for the wrong subject lets its holder act as that person through the API, and register a device under a new root, which the person's contacts see only as a changed security code |
| TLS in front of `sermod` | `sermod` serves plain HTTP, and every request carries a bearer token |

`SERMO_INSTALLATION_KEY` admits the assistant's member, whose routes are
not served yet. Leave it unset until they are and you mean to run one.

## Audit

Sermo, and the MLS code its devices and the server run, have had no
external security audit. [`SECURITY.md`](../SECURITY.md#audit) says what
has been tested instead.
