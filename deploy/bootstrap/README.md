# Bootstrap resources

The release pipeline never reads this directory. Everything it applies runs
again on every release, so everything it applies must be re-appliable, and
the resources here are not: a token Secret is minted once, and an identity
that could rewrite its own Role could grant itself anything. An operator
applies these files, once and again only when one changes.

`sermod` migrates its database at start, under the migrator's lock, so there
is no migration Job to run before a release. The Secrets the Deployment
reads (`sermo-db`, `sermod-authorizer`, `sermod-service-key` and
`platformd-internal-ca`) are created outside this tree and keep their names.

The policy that admits the core's Pods to platformd's internal TLS listener,
`sermod-platformd-tls`, is applied by platform's release
(`latere-ai/platform`, `deploy/prod`). No operator step remains for it.

## The rollout identity

`rollout-identity.yaml` is the account the release pipeline deploys with: a
ServiceAccount, a Role and RoleBinding in the `latere` namespace over the
kinds `deploy/prod` contains, and the token Secret bound to the account. An
installation elsewhere changes the namespace before applying it. A kind
added to `deploy/prod` is added to the Role and applied again by an
operator.

```sh
kubectl apply -f deploy/bootstrap/rollout-identity.yaml

NS=latere SA=sermod-rollout
kubeconfig=$(mktemp) && chmod 600 "$kubeconfig"
KUBECONFIG="$kubeconfig" kubectl config set-cluster latere-k8s \
  --server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
KUBECONFIG="$kubeconfig" kubectl config set clusters.latere-k8s.certificate-authority-data \
  "$(kubectl -n "$NS" get secret "$SA-token" -o jsonpath='{.data.ca\.crt}')"
KUBECONFIG="$kubeconfig" kubectl config set-credentials "$SA" \
  --token="$(kubectl -n "$NS" get secret "$SA-token" -o jsonpath='{.data.token}' | base64 -d)"
KUBECONFIG="$kubeconfig" kubectl config set-context "$SA" \
  --cluster=latere-k8s --user="$SA" --namespace="$NS"
KUBECONFIG="$kubeconfig" kubectl config use-context "$SA"

# The server-side dry run authorizes every object a release applies without
# changing any, so a Role that misses a kind fails here and not in a release.
KUBECONFIG="$kubeconfig" kubectl apply -k deploy/prod --dry-run=server

gh secret set SERMO_KUBECONFIG --repo latere-ai/sermo < "$kubeconfig"
rm "$kubeconfig"
gh variable set SERMO_RELEASE_DEPLOY --repo latere-ai/sermo --body 1
```

The `deploy` job of `.github/workflows/release.yml` runs only while the
repository variable `SERMO_RELEASE_DEPLOY` is set, so a fork, which sets
neither it nor the secret, publishes every artifact and deploys nothing.
Unsetting the variable turns the deploy off again.

Rotating the credential is deleting the token Secret, applying the identity
file again, and running the same steps.
