// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stub serves what the public origin serves for sermod: the API prefix,
// which answers an unauthenticated request with a 401 and a JSON error.
func stub(t *testing.T) *httptest.Server {
	return stubVersion(t, served)
}

// served is a version route that serves the build v1.2.3.
func served(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"version":"v1.2.3","commit":"","build_time":""}` + "\n"))
}

// stubVersion is stub with the version route a test chooses; nil leaves it
// unserved.
func stubVersion(t *testing.T, version http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if version != nil {
		mux.HandleFunc("GET /v1/messaging/version", version)
	}
	mux.HandleFunc("GET /v1/messaging/conversations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"missing_token","message":"This request needs a token."}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func script(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Join(filepath.Dir(file), "release.sh")
}

// run executes the script and returns its combined output and whether it
// exited zero. It skips when the tools the script needs are not on PATH: the
// gate's hermetic run puts only the Go toolchain there, and every ordinary
// run and CI job has them.
func run(t *testing.T, env ...string) (string, bool) {
	t.Helper()
	for _, cmd := range []string{"bash", "curl", "grep", "mktemp"} {
		if _, err := exec.LookPath(cmd); err != nil {
			t.Skipf("%s is not on PATH, so release.sh cannot run here", cmd)
		}
	}
	cmd := exec.CommandContext(context.Background(), "bash", script(t))
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func TestSmokePassesAgainstARoutedOrigin(t *testing.T) {
	srv := stub(t)
	evidence := filepath.Join(t.TempDir(), "smoke.md")
	out, ok := run(t, "BASE_URL="+srv.URL, "TAG=v1.2.3", "COMMIT=abc1234", "OUTPUT_MD="+evidence)
	if !ok {
		t.Fatalf("the smoke failed against a routed origin:\n%s", out)
	}
	md, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Release evidence", "- Tag: `v1.2.3`", "- Commit: `abc1234`", "- Origin: " + srv.URL, "- Served version: `v1.2.3`, equal to the tag"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("the evidence lacks %q:\n%s", want, md)
		}
	}
}

func TestSmokeFailsWhenTheServedVersionIsNotTheTag(t *testing.T) {
	srv := stub(t)
	out, ok := run(t, "BASE_URL="+srv.URL, "TAG=v1.2.4")
	if ok || !strings.Contains(out, "version mismatch: served v1.2.3, expected v1.2.4") {
		t.Fatalf("the smoke passed or did not name both versions (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeRecordsTheVersionWithNoTag(t *testing.T) {
	srv := stub(t)
	out, ok := run(t, "BASE_URL="+srv.URL)
	if !ok || !strings.Contains(out, "served version recorded (v1.2.3)") {
		t.Fatalf("want a pass that records the version (ok=%v):\n%s", ok, out)
	}
}

func TestSmokeFailsWhenTheVersionRouteIsNotServed(t *testing.T) {
	srv := stubVersion(t, nil)
	out, ok := run(t, "BASE_URL="+srv.URL, "TAG=v1.2.3")
	if ok || !strings.Contains(out, "GET /v1/messaging/version: expected 200, got 404") {
		t.Fatalf("the smoke passed or did not name the route (ok=%v):\n%s", ok, out)
	}
}

// TestSmokeFailsWhenTheOriginRoutesNothing is a rollout that lands without
// the ingress rule that claims the prefix: the origin answers 404.
func TestSmokeFailsWhenTheOriginRoutesNothing(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	out, ok := run(t, "BASE_URL="+srv.URL)
	if ok {
		t.Fatalf("the smoke passed against an origin that routes nothing:\n%s", out)
	}
	if !strings.Contains(out, "expected 401, got 404") {
		t.Errorf("the failure does not name the answer:\n%s", out)
	}
}

// TestSmokeFailsOnAForeignUnauthorized is a 401 from something that is not
// sermod: it carries no JSON error.
func TestSmokeFailsOnAForeignUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	out, ok := run(t, "BASE_URL="+srv.URL)
	if ok {
		t.Fatalf("the smoke passed on a 401 with no JSON error:\n%s", out)
	}
}

func TestSmokeFailsWhenTheServiceIsDown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	out, ok := run(t, "BASE_URL="+url)
	if ok {
		t.Fatalf("the smoke passed against a service that is down:\n%s", out)
	}
	if !strings.Contains(out, "no answer from") {
		t.Errorf("the failure does not say the service is down:\n%s", out)
	}
}

func TestSmokeRefusesWithNoTarget(t *testing.T) {
	out, ok := run(t, "BASE_URL=")
	if ok {
		t.Fatalf("the smoke passed with no BASE_URL:\n%s", out)
	}
	if !strings.Contains(out, "BASE_URL is required") {
		t.Errorf("the failure does not say what is missing:\n%s", out)
	}
}
