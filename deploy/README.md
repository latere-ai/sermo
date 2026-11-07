# Deploy

The maintainer's own installation of `sermod`, as Kustomize manifests. This
repository ships no base and no example overlay; an installation of your
own follows [`docs/install.md`](../docs/install.md).

| Directory | Holds |
|---|---|
| `prod/` | the maintainer's own installation, not an install path: the Deployment, Service, ServiceAccount, PodDisruptionBudget, NetworkPolicy and Ingress, and the ConfigMap generated from `sermod.env`. A release applies it through the `deploy` job of `.github/workflows/release.yml` only where the repository variable `SERMO_RELEASE_DEPLOY` is set, so a fork deploys nothing. It holds only manifests that are safe to apply again |
| `bootstrap/` | what the release never applies for that installation: the identity the `deploy` job runs as, applied once by an operator. Its [README](bootstrap/README.md) says how |
