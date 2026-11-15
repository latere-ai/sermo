// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"latere.ai/x/ci-gate/reap"
	"latere.ai/x/pkg/authkit/issuertest"
)

// These cases run against a real Postgres in an ephemeral container
// started once per test binary. Where no container runtime answers they
// skip and say so; the stand-in store of the other cases covers the
// wiring.

func TestMain(m *testing.M) {
	code := m.Run()
	terminate()
	os.Exit(code)
}

var (
	once      sync.Once
	serverURL string
	serverErr error
	container testcontainers.Container
)

// postgresURL is the URL of the container's server, started on first use.
func postgresURL(t *testing.T) string {
	t.Helper()
	once.Do(start)
	if serverErr != nil {
		t.Skipf("no container runtime answered, so the Postgres tests did not run: %v", serverErr)
	}
	return serverURL
}

func start() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	socket(ctx)
	if _, err := reap.Sweep(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "sweeping the containers of exited test binaries: %v\n", err)
	}
	ctr, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("sermo"),
		tcpostgres.WithUsername("sermo"),
		tcpostgres.WithPassword("sermo"),
		testcontainers.WithLabels(reap.Labels()),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute)),
	)
	if err != nil {
		if ctr != nil {
			err = errors.Join(err, ctr.Terminate(ctx))
		}
		serverErr = err
		return
	}
	container = ctr
	serverURL, serverErr = ctr.ConnectionString(ctx, "sslmode=disable")
}

func terminate() {
	if container == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := container.Terminate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "terminating the Postgres container: %v\n", err)
	}
	container = nil
}

// socket points the container library at a Podman machine where no
// DOCKER_HOST is set. Ryuk, the reaper container, is unreliable on
// rootless Podman, and TestMain terminates what this binary started.
func socket(ctx context.Context) {
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		if resolved, err := filepath.EvalSymlinks(strings.TrimPrefix(host, "unix://")); err == nil && strings.Contains(resolved, "podman") {
			setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
		}
		return
	}
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probe, "podman", "machine", "inspect", "--format", "{{.ConnectionInfo.PodmanSocket.Path}}").Output()
	if err != nil {
		return // no Podman, and start reports what the engine says
	}
	path := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if _, err := os.Stat(path); err != nil {
		return
	}
	setenv("DOCKER_HOST", "unix://"+path)
	setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
}

func setenv(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "setting %s: %v\n", key, err)
	}
}

// A server on Postgres opens the database, migrates it, serves a request
// that is kept in it, answers a ping, and closes; a second server over the
// same database reads what the first kept.
func TestPostgres(t *testing.T) {
	url := postgresURL(t)
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	key, _ := keys(t)
	o := Options{OIDCIssuers: []string{iss.URL()}, ServiceKey: key, DatabaseURL: url, Logger: quiet()}
	s, err := New(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if s.StoreKind() != "postgres" {
		t.Errorf("StoreKind = %q", s.StoreKind())
	}
	if err := s.Ping(t.Context()); err != nil {
		t.Errorf("Ping: %v", err)
	}
	token := iss.Mint(issuertest.Claims{Sub: "pg-alice"})
	register(t, s.Handler(), token, "pg-alice", "phone")
	s.Close()
	if err := s.Ping(t.Context()); err == nil {
		t.Error("Ping succeeded after Close")
	}

	again, err := New(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(again.Close)
	code, b := request(t, again.Handler(), "GET", Prefix+"/people/pg-alice/devices", token, nil)
	if code != 200 || !strings.Contains(string(b), "phone") {
		t.Errorf("the second server did not read the device the first kept: %d %s", code, b)
	}
}
