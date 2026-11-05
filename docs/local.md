# Running it locally

`sermod` on your own machine: built from source, a local OpenID Connect
issuer, and requests that show the server answering a signed-in person.
Nothing here survives a restart: with no database, `sermod` keeps
everything in the process.

`sermod` has no development mode and no static token. Every request but
the version needs a token from an OpenID Connect issuer, so a local run
needs one too. This page uses [Dex](https://dexidp.io/) in a container,
configured by [`docs/local/dex.yaml`](local/dex.yaml). Any issuer works
whose discovery document `sermod` can read and whose tokens name the
audience `sermo`.

The blocks run in order in one shell, from the root of a clone.

## What you need

Go 1.27 or newer, `git`, `curl`, `jq`, and Podman or Docker. The
commands say `podman`; `docker` takes the same arguments.

## Build

```sh
go build -o out/sermod ./cmd/sermod
./out/sermod -version
```

## An issuer

Dex with one user, `alice@example.com` with the password `password`, and
one client whose id is `sermo`. Dex addresses its ID tokens to the client
that asked, so a token for the client `sermo` carries the audience
`sermod` accepts by default.

```sh
podman run -d --name sermo-dex -p 127.0.0.1:5556:5556 \
  -v "$PWD/docs/local/dex.yaml:/etc/dex/config.yaml:ro" \
  ghcr.io/dexidp/dex:v2.43.1 dex serve /etc/dex/config.yaml

until curl -fs http://127.0.0.1:5556/dex/.well-known/openid-configuration > /dev/null; do sleep 1; done
```

The password grant gives a token without a browser:

```sh
TOKEN=$(curl -s http://127.0.0.1:5556/dex/token -u sermo:local-client-secret \
  -d grant_type=password -d username=alice@example.com -d password=password \
  -d scope=openid | jq -r .id_token)
```

The person the token names is its `sub` claim. Sermo knows a person by
that value alone, and every `person` in a path is one:

```sh
ME=$(echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | jq -Rr '@base64d | fromjson | .sub')
echo "$ME"
```

## Start sermod

```sh
SERMO_ADDR=127.0.0.1:8080 \
SERMO_OIDC_ISSUERS=http://127.0.0.1:5556/dex \
  ./out/sermod > out/sermod.out 2> out/sermod.log &

until curl -fs http://127.0.0.1:8080/readyz > /dev/null; do sleep 1; done
cat out/sermod.out
```

The first line says the store is in memory and that the member policy
decides: with no authorizer configured, a person acts on their own
devices and on the conversations they are in. The log, one JSON object
per line, is in `out/sermod.log`.

## Requests

The build it runs, which needs no token:

```sh
curl -s http://127.0.0.1:8080/v1/messaging/version
```

The server as an MLS external sender, which every conversation's group
names before it is created:

```sh
curl -s http://127.0.0.1:8080/v1/messaging/service -H "Authorization: Bearer $TOKEN" | jq .
```

Alice's directory, which is empty until a device registers, and her
conversations, of which there are none yet:

```sh
curl -s "http://127.0.0.1:8080/v1/messaging/people/$ME/devices" -H "Authorization: Bearer $TOKEN" | jq .
curl -s http://127.0.0.1:8080/v1/messaging/conversations -H "Authorization: Bearer $TOKEN" | jq .
```

A route that acts for a device needs the device named in `Sermo-Device`,
and refuses a device the person has not registered:

```sh
curl -s http://127.0.0.1:8080/v1/messaging/key-packages -H "Authorization: Bearer $TOKEN" | jq .
```

```json
{
  "error": {
    "code": "not_your_device",
    "message": "This device is not one of yours. Set it up again.",
    "details": {
      "detail": "the route speaks for a device: send Sermo-Device"
    }
  }
}
```

## A conversation

Everything past this point is signed and encrypted on a device: a device
record vouched for by the person's own key, key packages, and the MLS
messages of each conversation. `curl` cannot make them. A device does it
with [`latere.ai/x/sdk-go/messaging`](https://pkg.go.dev/latere.ai/x/sdk-go/messaging),
whose `Client` calls this API and whose `Policy` applies the same checks
`sermod` applies, over [`latere.ai/x/sdk-go/mls`](https://pkg.go.dev/latere.ai/x/sdk-go/mls).
[The API](api.md#the-flows) is the order of the calls.

## Stopping

```sh
kill %1
podman rm -f sermo-dex
```

## What next

- [Install](install.md): the image, Postgres and the keys of an
  installation that keeps what it holds.
- [Writing an authorizer](authorizer.md): who may start a conversation,
  add whom, and read what.
