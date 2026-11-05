# Security

Sermo carries the conversations of people who expect no one but each
other to read them. It delivers what their devices encrypt, keeps the
directory their devices trust, and checks every change to who is in a
conversation. This file is how to tell us when it fails at that, what
the project commits to, what it does not defend, and where its code
stands. [`docs/security.md`](docs/security.md) is the same for the
people who run `sermod` and build clients for it, with what the server
can see.

## Reporting a vulnerability

Report it through
[GitHub private vulnerability reporting](https://github.com/latere-ai/sermo/security/advisories/new),
or by email to security@latere.ai. Do not open a public issue for it.
The [organization's security policy](https://github.com/latere-ai/.github/blob/main/SECURITY.md)
says when you will hear back, how a fix is disclosed, and the safe harbor
for research that follows it.

Sermo is before its 1.0 release, and fixes ship in a new release of the
latest version. Earlier releases do not receive them.

These are the reports we most want: anything that lets someone read a
message without a member's keys; post to a conversation, or change who is
in it, without being a member the rules allow; make the server accept a
commit that an honest device refuses, or refuse one it would merge; list
a device in a person's directory that the person's own keys did not
vouch for; act without the authorizer's allow; or find a message, a key
or a secret of the configuration in a log line, a response or a column
it does not belong in. What [is not defended](#what-is-not-defended) is
not a vulnerability, but a report that one of those limits is wider than
written here is.

## What is protected

Each row is who could attack, what Sermo commits to against them, and
the test in this repository that holds the commitment. A control without
a test is a claim, and no claim is listed here.

| Who | What Sermo commits to | Held by |
|---|---|---|
| whoever runs the server or reads its database, its logs or its answers | the server never holds a key that opens what people write: a message, a Welcome, a backup key left for a new device, and a backup record are kept as the bytes a device sent. A message planted in a conversation appears in no log line and no response, and bytes planted in each value the store keeps appear in no other column, index or error | `TestConversation`, `TestBackupDeniedAndCanary`, `TestNothingLeavesTheBytesItWasHanded` |
| a caller with a valid token of another person | every route verifies the token and asks the authorizer before it reads or acts. A device that is not the caller's, or is revoked, is refused before anything is asked | `TestAuthenticateRefuses`, `TestDenied`, `TestDeniedDevices`, `TestDeniedInConversation`, `TestConversation` |
| any caller, when the authorizer cannot answer | the request is refused with `503` and changes nothing. An authorizer that allows the reserved question every authorizer must deny, or does not answer it, stops the server from starting | `TestAuthorizerUnavailable`, `TestAuthorizerAtStart`, `TestCheck` |
| a member who sends a change the conversation's rules forbid, such as a person who is not an owner adding someone | the commit is refused with `422` before it is kept, and the log does not change. The rules are the ones every device applies, from the same package | `TestConversation`, `TestSendRefusals` |
| a device that sends as another device | a message whose sender is not the calling device, with the key of its record, is refused | `TestSendRefusals` |
| two members, or two replicas, changing one conversation at once | the first commit of an epoch to pass is the epoch's, and the other is refused with `409 epoch_taken`, so every device sees one order. The database decides, not either replica | `TestConversation`, `TestTwoReplicasRace` |
| someone who holds a person's lost or stolen device | a record is taken only when it is vouched for under its person's root and signed by its own key; a record under a revoked key, a record that would replace another's key, and a record moved under another root are refused. On a revocation, the server proposes the removal of the device from every conversation of its person's | `TestRecordUnderARevokedKey`, `TestRecordBesideAnother`, `TestRecordMovedUnderAnotherRoot`, `TestARevokedKeyTakenMeanwhile`, `TestConversation` |
| a person removed from a conversation | a Welcome to it that they had not fetched is no longer handed out | `TestWelcomeAfterRemoval` |
| another person, about someone's history | a person's backup records are theirs alone to store and read | `TestBackupRecords` |
| whoever creates a conversation | a conversation starts only as a group of its creator's device alone, in the profile every device uses, with this server as its one external sender | `TestCreateRefusals` |
| a reader of the server's output and configuration | a database password, the authorizer's bearer and the server's key appear in no log line, error or printed setting | `TestStartFailures`, `TestErrorsNameTheVariableNotTheValue`, `TestSecretIsRedacted` |

## What is not defended

- **What the server can see.** It keeps who is in each conversation,
  every device of every person and its public keys, when each message
  was sent and by which device, its padded size, and every change to
  each group, which it reads in full to check it. An operator, or anyone
  who reads the database, learns who talks to whom and when.
  [What the server sees](docs/security.md#what-the-server-sees) lists
  it.
- **A server that lists a new root for a person.** The directory is as
  trustworthy as the roots each person's contacts pinned. A server that
  lists a new root for a person, with a device under it, can have that
  device added to conversations; the only sign on the contacts' devices
  is a changed security code. Such a root revokes nothing under the
  person's own roots and approves no backup key.
- **A server that withholds or delays.** It can drop messages, hold a
  device at an earlier epoch, or withhold a revocation from a device
  that never saw it.
- **A member that stops a conversation.** A commit's membership tag and
  confirmation tag need the epoch's secrets, which only members hold, so
  the server cannot check them. A member can send a commit whose tags
  are wrong: the server takes it as the epoch's, every other member
  refuses it, and the conversation goes no further. The commit names its
  sender, and the owners start a new conversation without them.
- **A history that proves less than it seems.** A message shared into a
  conversation's history, or kept in a backup, proves who signed it, not
  that it was sent to that conversation or when.
- **A revoked device.** It keeps the backup key it was given, which does
  not change on a revocation, and the epochs' secrets it held before its
  removal.
- **An authorizer that answers wrongly,** or an issuer that signs a token
  for the wrong person. Sermo refuses when no decision arrives and
  follows the one that does. With no authorizer, any signed-in person may
  start a conversation and add anyone whose identifier they know.
- **A compromised device or host.** A device holds its person's keys and
  reads what they read. The server's host holds the server's key.
- **Denial of service.** Sermo sets no rate limit of its own beyond the
  bounds on each request; an authorizer can refuse what it judges too
  much.

The assistant's member, a member whose keys the server would hold while
a conversation's owners let it in, is designed and not served. When it
is, a conversation where it is on will be readable by the installation
that runs it, as every member's device shows.

## Audit

Sermo has had no external security audit. Neither has the MLS
implementation it checks every commit with,
[`latere.ai/x/sdk-go/mls`](https://pkg.go.dev/latere.ai/x/sdk-go/mls),
nor the conversation rules and directory every device and the server
apply, [`latere.ai/x/sdk-go/messaging`](https://pkg.go.dev/latere.ai/x/sdk-go/messaging).
The MLS implementation passes the IETF MLS working group's
interoperability test vectors for the cipher suites it implements, which
tests that it conforms to RFC 9420, not that it is secure. Weigh that
before relying on Sermo where a failure of its encryption would put
someone at risk.

## Supply chain

Dependencies are checked for known vulnerabilities on every push. A
release is built from a tagged commit whose checks passed, through the
shared release workflows in [latere-ai/ci](https://github.com/latere-ai/ci).
The image is signed by the build workflow's identity, and the release
carries a bill of materials and `checksums.txt`, signed by the publish
workflow's identity, both run for this repository. The release workflow
verifies every release it publishes, and
[Install](docs/install.md#checking-a-release) has the commands that
verify one you downloaded.
