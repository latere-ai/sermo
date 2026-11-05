# Writing an authorizer

Sermo decides what MLS and a conversation's rules decide, the same way
every device does. Everything else about who may do what is yours: who
may talk to whom, how many conversations a person may start, blocks
between people, an account's standing, and who may read a conversation
as the assistant. `sermod` sends one question to an endpoint you write
for each request, and follows its answer. This page is the contract.

Without an endpoint, `sermod` decides by the
[member policy](#without-an-authorizer).

## The question

For every request that passes the token and device checks, `sermod`
sends one question to `SERMO_AUTHORIZER_URL`:

```http
POST <SERMO_AUTHORIZER_URL>
Authorization: Bearer <the contents of SERMO_AUTHORIZER_TOKEN_FILE>
Content-Type: application/json
```

```json
{
  "subject": "https://login.example.com|alice",
  "issuer": "https://login.example.com",
  "sub": "alice",
  "claims": {"iss": "https://login.example.com", "sub": "alice", "aud": "sermo", "exp": 1793982589},
  "action": "conversation.commit",
  "resource": {
    "kind": "Conversation",
    "id": "R3J5X6M2KQ7NPZ4TB2GH7YWC5D",
    "conversation_kind": "group",
    "people": ["alice", "bob"],
    "owners": ["alice"],
    "level": "off",
    "changes": ["add_people"],
    "add_people": ["carol"],
    "new_owners": ["alice"],
    "new_level": "off"
  },
  "request": {"id": "01JC2YB8M6Q3X5", "ip": "203.0.113.7", "user_agent": "example-app/1.0"}
}
```

- `subject` is the issuer and the `sub` joined by `|`, and `issuer` and
  `sub` are its two halves. A person in a conversation's `people` and
  `owners` is a `sub` alone.
- `claims` is every verified claim of the caller's token, verbatim.
  `sermod` reads none of them beyond `sub`; your policy reads whichever
  it needs.
- `action` is one of [the vocabulary](#the-vocabulary), and `resource` is
  what it acts on: its `kind`, its `id` when it has one, and the fields
  the vocabulary names for the action, flat beside them. A field `sermod`
  does not know for a request is absent.
- `request` is the request's id, the caller's address and its user
  agent. The id is for correlating logs.

## The answer

Answer `200` with a JSON body:

```json
{"allow": true, "ttl": 60}
```

```json
{"allow": false, "reason": "blocked"}
```

- `allow` decides. A body without it is no answer.
- `reason`, on a deny, reaches the caller in the error's `detail`, with
  `403 forbidden`. Write it for a developer.
- `ttl` is how many seconds `sermod` may reuse an allow for the same
  question; 60 when absent, and 600 at most. A deny is reused for 5
  seconds.

## Failing closed

`sermod` waits 5 seconds for an answer, and sends the question once more
when the connection failed before any answer began. A question with no
answer, a status other than `200` or a body without `allow` fails the
request with `503 authorizer_unavailable`, which is never cached and
which the client may retry. Nothing is changed by a request the
authorizer did not allow.

At start, `sermod` sends a question about the reserved id
`00000000-0000-0000-0000-000000000001`, which every authorizer must deny
for every subject and action. An endpoint that allows it, or does not
answer, stops the start: it is not reading the question.

## The vocabulary

The package [`authorizer`](../authorizer) declares it, and a test holds
the server to it.

| Kind | Action | Sent for | Fields |
|---|---|---|---|
| `Conversation` | `conversation.create` | creating a conversation | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.read` | every read of a conversation: its record, group info, messages and Welcomes | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.list` | listing a person's conversations | `person` |
| `Conversation` | `conversation.send` | sending an application message | `id`, `conversation_kind`, `people`, `owners`, `level`, `size` |
| `Conversation` | `conversation.commit` | a commit the rules accept, a proposal that is not a device leaving, and fetching the assistant's key package to turn the assistant on | `id`, `conversation_kind`, `people`, `owners`, `level`, `changes`, `add_people`, `remove_people`, `new_owners`, `new_level` |
| `Conversation` | `conversation.leave` | a proposal that removes its sender's own leaves | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.membership` | checking whether a person is one of the conversation's people | `id`, `conversation_kind`, `people`, `owners`, `level`, `person` |
| `Conversation` | `conversation.assistant_read` | reading the conversation as the assistant's member; not sent yet | `id`, `conversation_kind`, `people`, `owners`, `level` |
| `Conversation` | `conversation.assistant_post` | posting as the assistant's member; not sent yet | `id`, `conversation_kind`, `people`, `owners`, `level`, `asked_by` |
| `Device` | `device.register` | registering a device record | `person`, `root` |
| `Device` | `device.vouch` | leaving the backup key for a new device, and the new device taking it | `id`, `person` |
| `Device` | `device.list` | listing a person's records | `person` |
| `Device` | `device.delete` | revoking a device | `id`, `person` |
| `KeyPackage` | `key_package.publish` | publishing key packages, and reading how many are left | `person`, `device` |
| `KeyPackage` | `key_package.claim` | claiming a person's key packages to add them to a conversation | `person`, `conversation` |
| `Backup` | `backup.recovery` | the recovery record and the wrapped backup key, and storing and listing backup records | `person` |

The fields:

- `conversation_kind` is `one_on_one` or `group`. `people` and `owners`
  are the conversation's, in the order they joined and became owners, as
  the epoch the request comes to holds them. `level` is how far the
  assistant takes part: `off`, `reads_along` or `takes_part`.
- `changes` lists what a commit changes, of `add_people`,
  `remove_people`, `owners`, `level` and `devices`. `add_people` and
  `remove_people` are the people it adds and removes, and `new_owners`
  and `new_level` what it leaves.
- `size` is a sent message's length in bytes.
- `person` is whose record, key package or backup it is; on
  `conversation.membership` the person checked, and on
  `key_package.claim` the person claimed for. `root` is `true` when a
  device registers as a new root, vouched for by none of the person's
  records.
- `asked_by` is the person an answer posted as the assistant answers.

The assistant's two actions, and fetching its key package to turn it on,
are in the vocabulary because the routes that send them are designed;
`sermod` does not serve those routes yet.

## Without an authorizer

With `SERMO_AUTHORIZER_URL` unset, `sermod` decides by the member policy,
in process:

- A conversation whose one person is the caller may be created.
- Every other question about a conversation is allowed when the caller
  is one of its people, and a list is of the caller's own.
- The assistant's reads and posts are refused, since only a service in
  front of `sermod` knows who may speak as the assistant.
- Anyone signed in may list a person's devices and claim their key
  packages, which adding them to a conversation takes.
- Every other question about a device, a key package or a recovery
  record is allowed when it is the caller's own.

It sets no limit of its own: any signed-in person may start
conversations and add anyone whose subject they know. Run an authorizer
when the people who can sign in should not all reach one another.

## A token's own grants

A token minted from a stored key, one whose `token_use` claim is `pat`
(a personal access token) or `sak` (a service account key), may do only
what its grants name: RFC 9396 `authorization_details` entries of type
`latere-authz`, each naming actions as `sermo:<action>` and, optionally,
one resource id. The member policy applies them: a request no grant of
such a token covers is refused, whatever the policy would allow, and a
grant never allows what the policy refuses. Other tokens are decided by
the policy alone. An authorizer written with
[`latere.ai/x/pkg/authz/server`](https://pkg.go.dev/latere.ai/x/pkg/authz/server)
applies them the same way.

## Writing one

Any HTTP server that answers the question works. In Go,
[`latere.ai/x/pkg/authz/server`](https://pkg.go.dev/latere.ai/x/pkg/authz/server)
is the scaffold: it reads the envelope, refuses the reserved id and an
action outside the vocabulary (`authorizer.Vocabulary()` in this
module), applies a token's grants, and calls your decision.
[`latere.ai/x/pkg/authz/conformance`](https://pkg.go.dev/latere.ai/x/pkg/authz/conformance)
is a test suite your endpoint can run against the same vocabulary.
