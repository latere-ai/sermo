// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the tests of the release workflow's shape and of the
// Kubernetes example in deploy/examples/kubernetes. Each reads the files as
// text, because a workflow carries expressions the manifests do not.
package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// root is the repository root. A test runs in its package directory, which
// holds up under -trimpath, where a source path from runtime.Caller does not.
func root(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	return filepath.Join(dir, "..", "..")
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
// shape: the build stage builds, signs and attests the image; the publish
// stage tags the digest and creates the release; the verify stage reads it
// back.
func TestTheReleaseRunsThroughTheSharedStagesInOrder(t *testing.T) {
	text := workflow(t)
	needs := regexp.MustCompile(`(?m)^    needs: (.+)$`)
	for _, want := range []struct{ job, uses, needs string }{
		{"build", "image-build.yml", ""},
		{"publish", "image-publish.yml", "build"},
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

// TestTheReleaseDeploysNothing: the pipeline builds and publishes and
// reaches no cluster, so no job reads a kubeconfig secret or a variable that
// switches a rollout on, and none calls the shared deploy stage.
func TestTheReleaseDeploysNothing(t *testing.T) {
	text := workflow(t)
	for _, not := range []string{"SERMO_KUBECONFIG", "SERMO_RELEASE_DEPLOY", "image-deploy.yml", "kubectl"} {
		if strings.Contains(text, not) {
			t.Errorf("release.yml names %s; the release deploys nothing", not)
		}
	}
	if strings.Contains(text, "\n  deploy:\n") {
		t.Error("release.yml has a deploy job; the release deploys nothing")
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
	if len(versions) != 3 {
		t.Errorf("the workflow calls %d shared stages, want build, publish and verify", len(versions))
	}
	if distinct := slices.Compact(slices.Sorted(slices.Values(versions))); len(distinct) > 1 {
		t.Errorf("the shared stages are called at %v, want one version", distinct)
	}
}

// example is the Kubernetes example, relative to the repository root.
const example = "deploy/examples/kubernetes"

// TestTheExampleNamesThePublishedImage: the kustomization names the
// placeholder the Deployment runs once, with the published image behind it
// at a released tag, which a release updates.
func TestTheExampleNamesThePublishedImage(t *testing.T) {
	kustomization := read(t, example+"/kustomization.yaml")
	pin := regexp.MustCompile(`(?m)^  - name: sermod\n    newName: ghcr\.io/latere-ai/sermod\n    newTag: v\d+\.\d+\.\d+\n(?:[^ ]|$)`)
	if !pin.MatchString(kustomization) {
		t.Error(example + "/kustomization.yaml does not name the image sermod as ghcr.io/latere-ai/sermod, by a released tag")
	}
	if n := strings.Count(kustomization, "\n    newName: "); n != 1 {
		t.Errorf("%s/kustomization.yaml names %d images, want the one the release builds", example, n)
	}
	if !strings.Contains(read(t, example+"/deployment.yaml"), "          image: sermod\n") {
		t.Error("the Deployment does not run the image the kustomization names, under the placeholder name")
	}
}

// TestTheExampleSelectsOnlySermodPods: the one policy selects sermod's own
// Pods and no other's.
func TestTheExampleSelectsOnlySermodPods(t *testing.T) {
	text := read(t, example+"/networkpolicy.yaml")
	_, afterSpec, ok := strings.Cut(text, "\nspec:\n  podSelector:\n    matchLabels:\n")
	if !ok {
		t.Fatal(example + "/networkpolicy.yaml has no policy selecting Pods")
	}
	if !strings.HasPrefix(afterSpec, "      app.kubernetes.io/name: sermod\n") {
		t.Error("the policy does not select sermod's Pods")
	}
	if n := strings.Count(text, "\nkind: NetworkPolicy\n"); n != 1 {
		t.Errorf("%s/networkpolicy.yaml holds %d policies, want one", example, n)
	}
}

// TestTheExampleHoldsNoCredential: the example is a public file. It names
// the Secrets the Deployment reads, and holds none of their values.
func TestTheExampleHoldsNoCredential(t *testing.T) {
	dir := filepath.Join(root(t), example)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		text := read(t, example+"/"+e.Name())
		for _, not := range []string{"kind: Secret\n", "stringData:", "\ndata:", "BEGIN ", "_KEY=", "_SECRET=", "_TOKEN=", "://postgres", "postgres://"} {
			if strings.Contains(text, not) {
				t.Errorf("%s/%s holds %q; a credential belongs in a Secret created outside the tree", example, e.Name(), strings.TrimSpace(not))
			}
		}
	}
}
