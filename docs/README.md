# Documentation

For people who run `sermod`, build a client for it, or write the
authorizer it asks.

## Trying it

| Page | |
|---|---|
| [Running it locally](local.md) | `sermod` on your machine from a clone, with a local issuer, and requests that show it answering |

## Running it

| Page | |
|---|---|
| [Install](install.md) | the image and how to check it, Postgres and its pooler, the server's key, the probes, the network, and upgrading |
| [Configuration](configuration.md) | every `SERMO_*` variable, its default, what refuses a start, and telemetry |
| [Security](security.md) | what an installation guarantees, what the server sees, and what an operator keeps safe |

## Building against it

| Page | |
|---|---|
| [API](api.md) | the conventions, the flows a device follows from its first record to a conversation, backup records, the errors to branch on, and the limits |
| [Writing an authorizer](authorizer.md) | the question `sermod` sends, the answer, failing closed, the vocabulary, and the member policy without one |

The OpenAPI document is [`api/openapi.yaml`](../api/openapi.yaml). A
device's client is
[`latere.ai/x/sdk-go/messaging`](https://pkg.go.dev/latere.ai/x/sdk-go/messaging).

## Changing it

[`CONTRIBUTING.md`](../CONTRIBUTING.md) is how to build and test a change
and where code belongs. [`SECURITY.md`](../SECURITY.md) is how to report
a vulnerability.
