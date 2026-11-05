// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the tests of what the release pipeline deploys: the
// shape of the release workflow, and the production overlay and the rollout
// identity it is applied with. Each reads the files as text, because a
// workflow carries expressions the manifests do not.
package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// root is the repository root.
func root(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func read(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

func workflow(t *testing.T) string {
	t.Helper()
	return read(t, ".github/workflows/release.yml")
}

// job returns the block of one job, from its key under `jobs:` to the next
// line at the jobs' own indentation: the next job, or the comment above it.
func job(t *testing.T, text, name string) string {
	t.Helper()
	_, after, ok := strings.Cut(text, "\n  "+name+":\n")
	if !ok {
		t.Fatalf("the workflow has no job named %q", name)
	}
	lines := strings.Split(after, "\n")
	for i, line := range lines {
		if len(line) > 2 && strings.HasPrefix(line, "  ") && line[2] != ' ' {
			lines = lines[:i]
			break
		}
	}
	return "\n" + strings.Join(lines, "\n")
}

// stage is where the shared image release stages live.
const stage = "latere-ai/ci/.github/workflows/"

// TestTheReleaseRunsThroughTheSharedStagesInOrder holds the pipeline's
// shape: the build stage builds, signs and attests the image; the deploy
// stage rolls what it pushed; only then does the publish stage tag the
// digest and create the release, and the verify stage read it back.
func TestTheReleaseRunsThroughTheSharedStagesInOrder(t *testing.T) {
	text := workflow(t)
	needs := regexp.MustCompile(`(?m)^    needs: (.+)$`)
	for _, want := range []struct{ job, uses, needs string }{
		{"build", "image-build.yml", ""},
		{"deploy", "image-deploy.yml", "build"},
		{"publish", "image-publish.yml", "[build, deploy]"},
		{"verify", "release-verify.yml", "publish"},
	} {
		block := job(t, text, want.job)
		got := ""
		if m := needs.FindStringSubmatch(block); m != nil {
			got = m[1]
		}
		if got != want.needs {
			t.Errorf("%s needs %q, want %q", want.job, got, want.needs)
		}
		if !strings.Contains(block, "\n    uses: "+stage+want.uses+"@") {
			t.Errorf("%s does not call the shared stage %s", want.job, want.uses)
		}
	}
	for _, direct := range []string{"cosign", "anchore/sbom-action", "actions/attest-", "imagetools", "gh release"} {
		if strings.Contains(text, direct) {
			t.Errorf("release.yml names %s; the shared stages sign, attest, tag and publish", direct)
		}
	}
}

// TestTheDeployJobIsGatedAndCallsTheDeployStage holds the one job that
// reaches a cluster to the two things that keep it off every other
// repository: the repository variable that gates it and the secret it hands
// the shared stage.
func TestTheDeployJobIsGatedAndCallsTheDeployStage(t *testing.T) {
	block := job(t, workflow(t), "deploy")
	for _, want := range []string{
		"\n    if: ${{ vars.SERMO_RELEASE_DEPLOY != '' }}",
		"\n    uses: " + stage + "image-deploy.yml@v1\n",
		"\n      DEPLOY_KUBECONFIG: ${{ secrets.SERMO_KUBECONFIG }}",
		"\n    permissions:\n      contents: read\n",
		"\n      url: https://api.latere.ai\n",
		"\n      runs_on: ubuntu-latest\n",
		"\n      deployments: |\n        sermod\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the deploy job does not carry %q", strings.TrimSpace(want))
		}
	}
	// The stage owns the kubeconfig, the apply and the smoke; none of them
	// is written out again here.
	for _, gone := range []string{"kubectl", "kustomize", "sed -i", "tools/smoke/release.sh"} {
		if strings.Contains(block, gone) {
			t.Errorf("the deploy job runs %q itself; image-deploy.yml does", gone)
		}
	}
}

// TestTheDeployPassesOnlySermodByDigest: the build pushes the image by digest
// under no tag, and the publish stage gives the tag only after the deploy
// has passed, so the stage is given the digest and never the tag, under the
// name the overlay gives the image.
func TestTheDeployPassesOnlySermodByDigest(t *testing.T) {
	block := job(t, workflow(t), "deploy")
	want := "\n      images: sermod=${{ needs.build.outputs.ref_1 }}@${{ needs.build.outputs.digest_1 }}\n"
	if !strings.Contains(block, want) {
		t.Error("the deploy job does not pass sermod as the overlay's name for it, pinned by digest")
	}
	for _, not := range []string{"needs.build.outputs.images", "ref_2", "digest_2", ":${TAG}", "github.ref_name"} {
		if strings.Contains(block, not) {
			t.Errorf("the deploy job names %q; it passes only the sermod image, by digest", not)
		}
	}
	if n := strings.Count(block, "\n      images:"); n != 1 {
		t.Errorf("the deploy job has %d images inputs, want 1", n)
	}
}

// TestPublishAndVerifyTolerateASkippedDeploy: deploy is skipped on every
// repository that sets no SERMO_RELEASE_DEPLOY, and a job that leans on the
// implicit success() is skipped whenever a job above it is. Publish names
// each result, and fails on a deploy that failed or was cancelled.
func TestPublishAndVerifyTolerateASkippedDeploy(t *testing.T) {
	text := workflow(t)
	publish := job(t, text, "publish")
	for _, want := range []string{
		"always()",
		"needs.build.result == 'success'",
		"needs.deploy.result != 'failure'",
		"needs.deploy.result != 'cancelled'",
	} {
		if !strings.Contains(publish, want) {
			t.Errorf("publish does not carry %q in its condition", want)
		}
	}
	// The smoke evidence exists only when the deploy ran; an evidence
	// pattern that names no file fails the publish stage.
	if !strings.Contains(publish, "evidence: ${{ needs.deploy.result == 'success' && 'smoke-evidence' || '' }}") {
		t.Error("publish does not name the smoke evidence only when the deploy succeeded")
	}
	verify := job(t, text, "verify")
	if !strings.Contains(verify, "if: ${{ always() && needs.publish.result == 'success' }}") {
		t.Error("verify does not run on a skipped deploy")
	}
}

// TestEveryThirdPartyActionIsPinned keeps every `uses:` outside latere-ai/ci
// on a commit, and the shared stages on one release tag of it, so they agree
// on what passes between them.
func TestEveryThirdPartyActionIsPinned(t *testing.T) {
	commit := regexp.MustCompile(`^[0-9a-f]{40}$`)
	release := regexp.MustCompile(`^v\d+(\.\d+\.\d+)?$`)
	var versions []string
	for i, line := range strings.Split(workflow(t), "\n") {
		ref, ok := strings.CutPrefix(strings.TrimSpace(line), "uses: ")
		if !ok {
			continue
		}
		ref, _, _ = strings.Cut(ref, " ")
		name, version, found := strings.Cut(ref, "@")
		switch {
		case !found:
			t.Errorf("release.yml:%d: %s names no version", i+1, ref)
		case strings.HasPrefix(name, stage):
			if !commit.MatchString(version) && !release.MatchString(version) {
				t.Errorf("release.yml:%d: %s is called at %q, neither a commit nor a release tag", i+1, name, version)
			}
			versions = append(versions, version)
		case !commit.MatchString(version):
			t.Errorf("release.yml:%d: %s is pinned to %q, which is not a commit", i+1, ref, version)
		}
	}
	if len(versions) != 4 {
		t.Errorf("the workflow calls %d shared stages, want build, deploy, publish and verify", len(versions))
	}
	if distinct := slices.Compact(slices.Sorted(slices.Values(versions))); len(distinct) > 1 {
		t.Errorf("the shared stages are called at %v, want one version", distinct)
	}
}

// kinds is the Kubernetes resource each kind in deploy/prod is applied as.
var kinds = map[string]string{
	"Deployment":          "deployments",
	"Service":             "services",
	"ServiceAccount":      "serviceaccounts",
	"ConfigMap":           "configmaps",
	"Ingress":             "ingresses",
	"NetworkPolicy":       "networkpolicies",
	"PodDisruptionBudget": "poddisruptionbudgets",
}

// prodResources is the set of resources deploy/prod applies: the kind of
// every document of its manifests, and ConfigMap where the kustomization
// generates one.
func prodResources(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(root(t), "deploy/prod")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	kind := regexp.MustCompile(`(?m)^kind: (\w+)\s*$`)
	var out []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".yaml" || e.Name() == "kustomization.yaml" {
			continue
		}
		for _, m := range kind.FindAllStringSubmatch(read(t, "deploy/prod/"+e.Name()), -1) {
			resource, ok := kinds[m[1]]
			if !ok {
				t.Errorf("deploy/prod/%s holds a %s, which the rollout identity's grant does not cover; add it to deploy/bootstrap/rollout-identity.yaml and to this test", e.Name(), m[1])
			}
			out = append(out, resource)
		}
	}
	if strings.Contains(read(t, "deploy/prod/kustomization.yaml"), "configMapGenerator:") {
		out = append(out, "configmaps")
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TestTheRolloutIdentityCoversExactlyWhatProdApplies: the Role allows apply
// on the kinds deploy/prod holds and no others, never touches Secrets, and
// never deletes; the token Secret is bound to the account it names.
func TestTheRolloutIdentityCoversExactlyWhatProdApplies(t *testing.T) {
	identity := read(t, "deploy/bootstrap/rollout-identity.yaml")
	role := identity[strings.Index(identity, "kind: Role\n"):strings.Index(identity, "kind: RoleBinding")]

	var granted []string
	list := regexp.MustCompile(`(?m)^\s+resources: \[(.*)\]\s*$`)
	for _, m := range list.FindAllStringSubmatch(role, -1) {
		for r := range strings.SplitSeq(m[1], ",") {
			granted = append(granted, strings.Trim(strings.TrimSpace(r), `"`))
		}
	}
	slices.Sort(granted)
	granted = slices.Compact(granted)
	if want := prodResources(t); !slices.Equal(granted, want) {
		t.Errorf("the Role grants %v, deploy/prod applies %v", granted, want)
	}
	for _, not := range []string{`"secrets"`, `"delete"`, `"namespaces"`, `"*"`, "ClusterRole"} {
		if strings.Contains(identity, not) {
			t.Errorf("the rollout identity names %s; it holds no such grant", not)
		}
	}
	if !strings.Contains(role, `resources: ["deployments"]`+"\n"+`    verbs: ["watch"]`) {
		t.Error("the Role does not let the rollout watch the Deployment")
	}
	for _, want := range []string{
		"name: sermod-rollout\n  namespace: latere",
		"kubernetes.io/service-account.name: sermod-rollout",
		"type: kubernetes.io/service-account-token",
		"the `SERMO_KUBECONFIG` repository secret",
	} {
		if !strings.Contains(identity, want) {
			t.Errorf("the rollout identity does not carry %q", want)
		}
	}
}

// TestProdNamesTheImageTheDeployPins: the deploy stage sets the image by the
// name the overlay gives it, so the kustomization names the placeholder the
// Deployment runs once, with the published image behind it.
func TestProdNamesTheImageTheDeployPins(t *testing.T) {
	kustomization := read(t, "deploy/prod/kustomization.yaml")
	pin := regexp.MustCompile(`(?m)^  - name: sermod\n    newName: ghcr\.io/latere-ai/sermod\n    newTag: v\d+\.\d+\.\d+\n    digest: sha256:[0-9a-f]{64}\n`)
	if !pin.MatchString(kustomization) {
		t.Error("deploy/prod/kustomization.yaml does not name the image sermod as ghcr.io/latere-ai/sermod, by a released tag and digest")
	}
	if n := strings.Count(kustomization, "\n    newName: "); n != 1 {
		t.Errorf("deploy/prod/kustomization.yaml names %d images, want the one the release builds", n)
	}
	if !strings.Contains(read(t, "deploy/prod/deployment.yaml"), "          image: sermod\n") {
		t.Error("the Deployment does not run the image the overlay names, under the placeholder name")
	}
}

// TestProdSelectsOnlyItsOwnPods: a rollout identity may write an object that
// selects its own service's Pods and no other's, so every selector at the
// top of a policy in deploy/prod names sermod. The policy that selects
// platformd's Pods is in deploy/bootstrap.
func TestProdSelectsOnlyItsOwnPods(t *testing.T) {
	text := read(t, "deploy/prod/networkpolicy.yaml")
	_, afterSpec, ok := strings.Cut(text, "\nspec:\n  podSelector:\n    matchLabels:\n")
	if !ok {
		t.Fatal("deploy/prod/networkpolicy.yaml has no policy selecting Pods")
	}
	if !strings.HasPrefix(afterSpec, "      app.kubernetes.io/name: sermod\n") {
		t.Error("the policy in deploy/prod does not select the core's Pods")
	}
	if n := strings.Count(text, "\nkind: NetworkPolicy\n"); n != 1 {
		t.Errorf("deploy/prod/networkpolicy.yaml holds %d policies, want the core's alone", n)
	}
	if !strings.Contains(read(t, "deploy/bootstrap/networkpolicy-platformd-tls.yaml"), "      app: platformd\n") {
		t.Error("deploy/bootstrap does not hold the policy that admits the core to platformd")
	}
}

// TestProdHoldsNoCredential: the overlay is a public file. It names the
// Secrets the Deployment reads, and holds none of their values.
func TestProdHoldsNoCredential(t *testing.T) {
	dir := filepath.Join(root(t), "deploy/prod")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		text := read(t, "deploy/prod/"+e.Name())
		for _, not := range []string{"kind: Secret\n", "stringData:", "\ndata:", "BEGIN ", "_KEY=", "_SECRET=", "_TOKEN=", "://postgres", "postgres://"} {
			if strings.Contains(text, not) {
				t.Errorf("deploy/prod/%s holds %q; a credential belongs in a Secret created outside the tree", e.Name(), strings.TrimSpace(not))
			}
		}
	}
}
