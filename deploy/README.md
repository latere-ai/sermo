# Deploy

Examples for running `sermod` yourself. This repository ships no base to
build on; an installation follows [`docs/install.md`](../docs/install.md),
and an example here is a starting point to copy and adapt.

| Directory | Holds |
|---|---|
| `examples/kubernetes/` | a Kustomize installation on Kubernetes: the Deployment, Service, ServiceAccount, PodDisruptionBudget, NetworkPolicy and Ingress, and the ConfigMap generated from `sermod.env`. Places marked "Fill in" hold placeholders such as `sermo.example.com` for you to replace; the Secrets it reads are created outside it. Each release updates the image tag in its `kustomization.yaml` |

A release publishes the image and rolls nothing out.
