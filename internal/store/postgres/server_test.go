// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"latere.ai/x/ci-gate/reap"

	"latere.ai/x/sermo/internal/store/postgres"
)

// The tests run against a real server, because half of what this store
// is for lives in Postgres and not in Go: the row lock behind an append
// that lost a race, the skip of a key package another claim holds, the
// transaction behind a refused commit.
//
// The server is an ephemeral container started once per test binary.
// Where no container runtime answers, every case that needs it skips and
// says so; the memory store's run of the same suite still covers the
// contract.
//
// A binary that never reaches TestMain's terminate, because it panicked
// on -timeout or was killed, leaves its container to the next sweep: the
// container carries the labels of latere.ai/x/ci-gate/reap, naming the
// process that owns it, and every start removes the ones whose owner has
// exited.

// TestMain terminates the container this binary started, whatever the
// tests did, so a failed run leaves no server behind.
func TestMain(m *testing.M) {
	code := m.Run()
	terminate()
	os.Exit(code)
}

// open is a store on one database, closed when the test ends.
func open(t *testing.T, o postgres.Options) *postgres.Store {
	t.Helper()
	s, err := postgres.Open(context.Background(), o)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// execMode is dsn with the query mode a transaction pooler's URL carries,
// default_query_exec_mode=exec: no statement is prepared or described,
// and every parameter is encoded from its Go type and sent as text.
func execMode(t *testing.T, dsn string) string {
	t.Helper()
	return withQuery(t, dsn, "default_query_exec_mode", "exec")
}

// withQuery is dsn with one query parameter set.
func withQuery(t *testing.T, dsn, key, value string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("the database URL: %v", err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// execute runs statements on one database.
func execute(t *testing.T, dsn string, statements ...string) {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Errorf("closing the connection: %v", err)
		}
	}()
	for _, statement := range statements {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("running %q: %v", statement, err)
		}
	}
}

// database creates an empty database on the server and returns its URL,
// so one case cannot read another's rows and the migrations run on each.
// The words after the name are the create's own, a locale among them.
func database(t *testing.T, admin string, with ...string) string {
	t.Helper()
	name := "sermo_" + strings.ToLower(rand.Text()[:12])
	execute(t, admin, strings.Join(append([]string{"create database", name}, with...), " "))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drop, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Errorf("connecting to drop the database: %v", err)
			return
		}
		defer func() {
			if err := drop.Close(ctx); err != nil {
				t.Errorf("closing the connection: %v", err)
			}
		}()
		if _, err := drop.Exec(ctx, "drop database if exists "+name+" with (force)"); err != nil {
			t.Errorf("dropping the database: %v", err)
		}
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("the server URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

var (
	once      sync.Once
	serverURL string
	serverErr error
	container testcontainers.Container
)

// sweep and run reach the container engine; variables so a test can
// stand in for it.
var (
	sweep = reap.Sweep
	run   = tcpostgres.Run
)

// server is the Postgres every case runs against, started once per
// binary.
func server(t *testing.T) string {
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
	if _, err := sweep(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "sweeping the containers of exited test binaries: %v\n", err)
	}
	ctr, err := run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("sermo_admin"),
		tcpostgres.WithUsername("sermo"),
		tcpostgres.WithPassword("sermo"),
		testcontainers.WithLabels(reap.Labels()),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute)),
	)
	if err != nil {
		// A container that started and then failed its wait comes back
		// with the error, and nothing else holds it.
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
// Docker socket answers, which is what a developer on macOS has. Ryuk,
// the reaper container, is unreliable on rootless Podman, and TestMain
// terminates what this binary started anyway.
func socket(ctx context.Context) {
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		reaperFor(strings.TrimPrefix(host, "unix://"))
		return
	}
	for _, path := range []string{"/var/run/docker.sock", filepath.Join(os.Getenv("HOME"), ".docker/run/docker.sock")} {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			reaperFor(path)
			return
		}
	}
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := runPodman(probe)
	if err != nil {
		return // no Podman either, and start reports what the engine says
	}
	path := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if info, err := os.Stat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		return
	}
	setenv("DOCKER_HOST", "unix://"+path)
	setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
}

// reaperFor turns Ryuk off where the Docker socket that answers is a
// Podman machine's under another name: the link macOS's Podman helper
// installs at /var/run/docker.sock is one, and Ryuk there asks for a
// bridge network the machine does not have, which skips every case.
func reaperFor(path string) {
	if onPodman(path) {
		setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
	}
}

func setenv(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "setting %s: %v\n", key, err)
	}
}

// onPodman reports whether a socket path resolves into a Podman
// machine's directory.
func onPodman(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	return strings.Contains(resolved, "podman")
}

func runPodman(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "podman", "machine", "inspect", "--format", "{{.ConnectionInfo.PodmanSocket.Path}}").Output()
	if err != nil {
		return "", fmt.Errorf("asking podman for its socket: %w", err)
	}
	return string(out), nil
}

// TestTheReaperIsOffBehindAPodmanLink: a Docker socket that is a link
// into a Podman machine's directory is Podman, and the reaper is turned
// off for it; a Docker socket of Docker's own leaves the reaper as the
// library sets it.
func TestTheReaperIsOffBehindAPodmanLink(t *testing.T) {
	dir := t.TempDir()
	machine := filepath.Join(dir, "podman", "machine")
	if err := os.MkdirAll(machine, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(machine, "podman.sock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "docker.sock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(dir, "docker", "docker.sock")
	if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "")
	reaperFor(own)
	if got := os.Getenv("TESTCONTAINERS_RYUK_DISABLED"); got != "" {
		t.Fatalf("Docker's own socket turned the reaper off: %q", got)
	}
	reaperFor(filepath.Join(dir, "absent.sock"))
	if got := os.Getenv("TESTCONTAINERS_RYUK_DISABLED"); got != "" {
		t.Fatalf("a socket that does not resolve turned the reaper off: %q", got)
	}
	reaperFor(link)
	if got := os.Getenv("TESTCONTAINERS_RYUK_DISABLED"); got != "true" {
		t.Fatalf("a link into a Podman machine left the reaper at %q", got)
	}
}

// stoppable records Terminate. It embeds the interface, left nil, so it
// satisfies testcontainers.Container with only Terminate implemented.
type stoppable struct {
	testcontainers.Container
	terminated int
}

func (s *stoppable) Terminate(context.Context, ...testcontainers.TerminateOption) error {
	s.terminated++
	return nil
}

// engine stands in for the container engine for one call of start: sweep
// and run are recorded, run answers with ctr and runErr, and the server
// this binary holds, if a case started one, is put back afterwards for
// TestMain to terminate.
func engine(t *testing.T, ctr *tcpostgres.PostgresContainer, runErr error) *[]string {
	t.Helper()
	// A DOCKER_HOST that is not Podman keeps socket from asking the
	// machine for its socket or setting anything.
	t.Setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
	prevSweep, prevRun := sweep, run
	prevURL, prevErr, prevContainer := serverURL, serverErr, container
	t.Cleanup(func() {
		sweep, run = prevSweep, prevRun
		serverURL, serverErr, container = prevURL, prevErr, prevContainer
	})
	var calls []string
	sweep = func(context.Context) (int, error) {
		calls = append(calls, "sweep")
		return 0, nil
	}
	run = func(_ context.Context, _ string, opts ...testcontainers.ContainerCustomizer) (*tcpostgres.PostgresContainer, error) {
		req := testcontainers.GenericContainerRequest{}
		for _, o := range opts {
			if err := o.Customize(&req); err != nil {
				t.Fatal(err)
			}
		}
		for k, v := range reap.Labels() {
			if req.Labels[k] != v {
				t.Errorf("the container's label %s = %q, want %q", k, req.Labels[k], v)
			}
		}
		calls = append(calls, "run")
		return ctr, runErr
	}
	return &calls
}

// TestAFailedStartStopsTheContainerItMade: a container that started and
// then failed its wait comes back with the error, and is stopped rather
// than left for nothing to hold.
func TestAFailedStartStopsTheContainerItMade(t *testing.T) {
	fake := &stoppable{}
	engine(t, &tcpostgres.PostgresContainer{Container: fake}, errors.New("wait until ready: deadline exceeded"))
	start()
	if fake.terminated != 1 {
		t.Fatalf("the failed container was terminated %d times, want once", fake.terminated)
	}
	if serverErr == nil {
		t.Fatal("the failed start reported no error, so the cases would not skip")
	}
}

// TestAStartSweepsThenLabels: every start removes what exited test
// binaries left, then labels its own container with its owner, so the
// next sweep can tell whether the process that started it still runs.
func TestAStartSweepsThenLabels(t *testing.T) {
	calls := engine(t, nil, errors.New("stop after the request"))
	start()
	if got := strings.Join(*calls, ","); got != "sweep,run" {
		t.Fatalf("calls = %s, want a sweep before the start", got)
	}
	if serverErr == nil {
		t.Fatal("the failed start reported no error")
	}
}
