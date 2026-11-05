// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authz/stub"
	"latere.ai/x/pkg/otel"
	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
	"latere.ai/x/sermo/internal/store/postgres"
	"latere.ai/x/sermo/internal/version"
)

// syncBuffer is a buffer two goroutines write and read.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func file(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A flag it does not know or an argument is a usage error; -version
// prints the version.
func TestUsage(t *testing.T) {
	for _, args := range [][]string{{"-nope"}, {"serve"}} {
		var stderr bytes.Buffer
		if code := run(t.Context(), args, env(nil), io.Discard, &stderr); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	var stdout bytes.Buffer
	if code := run(t.Context(), []string{"-version"}, env(nil), &stdout, io.Discard); code != 0 || strings.TrimSpace(stdout.String()) == "" {
		t.Errorf("-version: exit %d, printed %q", code, stdout.String())
	}
}

// A release the linker stamps is the version -version prints, which the
// release pipeline compares with the tag.
func TestStampedVersion(t *testing.T) {
	old := version.Version
	t.Cleanup(func() { version.Version = old })
	version.Version = "v9.8.7"
	var stdout bytes.Buffer
	if code := run(t.Context(), []string{"-version"}, env(nil), &stdout, io.Discard); code != 0 || stdout.String() != "v9.8.7\n" {
		t.Errorf("-version: exit %d, printed %q, want the stamped v9.8.7", code, stdout.String())
	}
}

// Settings it cannot start with, an address it cannot listen on, and a
// database with no store in the build are each a failure that names the
// variable.
func TestStartFailures(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	_, seed := seedFile(t)
	for name, c := range map[string]struct {
		vars map[string]string
		want string
	}{
		"no issuer":    {map[string]string{}, "SERMO_OIDC_ISSUERS"},
		"a bad listen": {map[string]string{"SERMO_OIDC_ISSUERS": iss.URL(), "SERMO_ADDR": "127.0.0.1:-1"}, "SERMO_ADDR"},
		"a database that does not answer": {map[string]string{"SERMO_OIDC_ISSUERS": iss.URL(),
			"SERMO_DATABASE_URL":     "postgres://sermo:" + canaryPassword + "@127.0.0.1:1/sermo?connect_timeout=2",
			"SERMO_SERVICE_KEY_FILE": seed}, "SERMO_DATABASE_URL"},
	} {
		var stderr bytes.Buffer
		if code := run(t.Context(), nil, env(c.vars), io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr.String())
		}
		if strings.Contains(stderr.String(), canaryPassword) {
			t.Errorf("%s: the database's password reached the output: %q", name, stderr.String())
		}
	}
}

// canaryPassword is a database password no output may carry.
const canaryPassword = "canary-db-password-6c1f"

// closing is a store kept in a database, with what the server did to it.
type closing struct {
	store.Store
	pings, closes atomic.Int32
}

func (c *closing) Ping(context.Context) error { c.pings.Add(1); return nil }
func (c *closing) Close()                     { c.closes.Add(1) }

// A database URL opens the Postgres store with both endpoints the
// settings name, which readiness pings and a stop closes once.
func TestDurableStore(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	_, seed := seedFile(t)
	db := &closing{Store: memory.New(time.Now)}
	var opened postgres.Options
	was := openPostgres
	openPostgres = func(_ context.Context, o postgres.Options) (durable, error) { opened = o; return db, nil }
	t.Cleanup(func() { openPostgres = was })
	s := start(t, map[string]string{"SERMO_OIDC_ISSUERS": iss.URL(), "SERMO_ADDR": "127.0.0.1:0",
		"SERMO_DATABASE_URL": "postgres://direct.example/sermo", "SERMO_DATABASE_POOL_URL": "postgres://pooled.example/sermo",
		"SERMO_SERVICE_KEY_FILE": seed})
	if !strings.Contains(s.line, "store=postgres") {
		t.Errorf("the start line: %q", s.line)
	}
	if opened.URL != "postgres://direct.example/sermo" || opened.PoolURL != "postgres://pooled.example/sermo" {
		t.Errorf("opened %+v", opened)
	}
	if code, _ := get(t, s.base+"/readyz", ""); code != http.StatusOK || db.pings.Load() == 0 {
		t.Errorf("/readyz: %d after %d pings", code, db.pings.Load())
	}
	s.stop(t)
	if n := db.closes.Load(); n != 1 {
		t.Errorf("the store was closed %d times", n)
	}
}

// An authorizer that cannot answer the probe stops the start; one that
// refuses it is the authorizer the server asks.
func TestAuthorizerAtStart(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	authz := stub.New(t, stub.WithToken(rand.Text()), stub.WithVocabulary(authorizer.Vocabulary()))
	vars := map[string]string{
		"SERMO_OIDC_ISSUERS": iss.URL(), "SERMO_ADDR": "127.0.0.1:0",
		"SERMO_AUTHORIZER_URL": authz.URL(), "SERMO_AUTHORIZER_TOKEN_FILE": file(t, authz.Token()),
	}
	authz.Fail(http.StatusInternalServerError)
	var stderr bytes.Buffer
	if code := run(t.Context(), nil, env(vars), io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "probe") {
		t.Errorf("an authorizer that fails: exit %d, stderr %q", code, stderr.String())
	}
	authz.Resume()
	s := start(t, vars)
	if !strings.Contains(s.line, "authorizer=remote") {
		t.Errorf("the start line: %q", s.line)
	}
	s.stop(t)
}

// running is a server a test started.
type running struct {
	base   string
	line   string
	cancel context.CancelFunc
	code   chan int
	output *syncBuffer
}

// start runs the server with a short drain and returns once it listens.
func start(t *testing.T, vars map[string]string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	pr, pw := io.Pipe()
	output := &syncBuffer{}
	r := &running{cancel: cancel, code: make(chan int, 1), output: output}
	go func() {
		r.code <- runWith(ctx, nil, env(vars), io.MultiWriter(pw, output), output, options{drain: 300 * time.Millisecond})
		_ = pw.Close()
	}()
	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		cancel()
		t.Fatalf("no start line: %v; output %s", err, output.String())
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	r.line = line
	_, after, ok := strings.Cut(line, "listening on ")
	if !ok {
		t.Fatalf("the start line names no address: %q", line)
	}
	r.base = "http://" + strings.Fields(after)[0]
	return r
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case code := <-r.code:
		if code != 0 {
			t.Errorf("exit %d after a stop; output %s", code, r.output.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not stop")
	}
}

func get(t *testing.T, url, token string) (int, []byte) {
	t.Helper()
	return do(t, http.MethodGet, url, token, nil)
}

func do(t *testing.T, method, url, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, b
}

func seedFile(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), file(t, base64.StdEncoding.EncodeToString(seed))
}

// The server serves the probes and the API, registers a device through
// it, fails readiness as it stops, and exits cleanly. Neither the
// authorizer's token nor the service key reaches its output.
func TestServe(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	authz := stub.New(t, stub.WithToken("canary-"+rand.Text()), stub.WithVocabulary(authorizer.Vocabulary()), stub.WithAllow(iss.URL()+"|alice"))
	key, seed := seedFile(t)
	s := start(t, map[string]string{
		"SERMO_OIDC_ISSUERS": iss.URL(), "SERMO_ADDR": "127.0.0.1:0", "SERMO_SERVICE_KEY_FILE": seed,
		"SERMO_AUTHORIZER_URL": authz.URL(), "SERMO_AUTHORIZER_TOKEN_FILE": file(t, authz.Token()),
	})
	for _, path := range []string{"/livez", "/readyz", "/version"} {
		if code, body := get(t, s.base+path, ""); code != http.StatusOK {
			t.Errorf("%s: %d %s", path, code, body)
		}
	}
	if code, _ := get(t, s.base+httpapi.Prefix+"/people/alice/devices", ""); code != http.StatusUnauthorized {
		t.Errorf("a request with no token: %d", code)
	}
	// The build identity is public below the prefix the ingress forwards,
	// with no token, and is the body the root serves.
	root, rootBody := get(t, s.base+"/version", "")
	under, underBody := get(t, s.base+httpapi.Prefix+"/version", "")
	var build struct {
		Version string `json:"version"`
	}
	if under != http.StatusOK || root != http.StatusOK || !bytes.Equal(rootBody, underBody) ||
		json.Unmarshal(underBody, &build) != nil || build.Version != otel.Version(version.Version) {
		t.Errorf("%s/version: %d %s, the root's: %d %s", httpapi.Prefix, under, underBody, root, rootBody)
	}
	if code, _ := do(t, http.MethodPost, s.base+httpapi.Prefix+"/version", "", nil); code == http.StatusOK {
		t.Errorf("POST %s/version answered %d", httpapi.Prefix, code)
	}

	token := iss.Mint(issuertest.Claims{Sub: "alice"})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := messaging.NewDeviceRecord("alice", "phone", priv, enc.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if code, b := do(t, http.MethodPut, s.base+httpapi.Prefix+"/devices/phone", token, body); code != http.StatusNoContent {
		t.Fatalf("registering a device: %d %s", code, b)
	}
	code, b := get(t, s.base+httpapi.Prefix+"/people/alice/devices", token)
	var list httpapi.DeviceList
	if code != http.StatusOK || json.Unmarshal(b, &list) != nil || len(list.Records) != 1 {
		t.Fatalf("the directory: %d %s", code, b)
	}
	code, b = get(t, s.base+httpapi.Prefix+"/service", token)
	var service httpapi.Service
	if code != http.StatusOK || json.Unmarshal(b, &service) != nil || !bytes.Equal(service.ExternalSender.SignatureKey, key.Public().(ed25519.PublicKey)) {
		t.Errorf("the service names another key than the one of SERMO_SERVICE_KEY_FILE: %d %s", code, b)
	}

	s.cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if code, _ := get(t, s.base+"/readyz", ""); code == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness did not fail as the server stopped")
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.stop(t)
	out := s.output.String()
	for name, secret := range map[string]string{"the authorizer's token": authz.Token(), "the service key": base64.StdEncoding.EncodeToString(key.Seed())} {
		if strings.Contains(out, secret) {
			t.Errorf("%s reached the output", name)
		}
	}
}

// A request still running when the server stops ends with the stop,
// before the grace period, so a waiting read does not hold the stop up.
func TestStopEndsWaitingRequests(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	srv := &server{stopping: new(atomic.Bool), handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		w.WriteHeader(http.StatusOK)
	})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, srv, 0, slog.New(slog.DiscardHandler)) }()
	answered := make(chan int, 1)
	go func() {
		res, err := http.Get("http://" + ln.Addr().String())
		if err != nil {
			answered <- 0
			return
		}
		_ = res.Body.Close()
		answered <- res.StatusCode
	}()
	<-started
	begun := time.Now()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code := <-answered; code != http.StatusOK {
		t.Errorf("the waiting request answered %d", code)
	}
	if took := time.Since(begun); took > gracePeriod/2 {
		t.Errorf("the stop took %v", took)
	}
	if !srv.stopping.Load() {
		t.Error("readiness was not failed on the stop")
	}
}

// A listener that fails is the serve's error.
func TestServeListenerFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	srv := &server{stopping: new(atomic.Bool), handler: http.NotFoundHandler()}
	if err := serve(t.Context(), ln, srv, 0, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("serving on a closed listener succeeded")
	}
}

// fakeSweeper answers each sweep in turn.
type fakeSweeper struct {
	mu      sync.Mutex
	answers []error
	calls   int
	done    chan struct{}
}

func (f *fakeSweeper) Sweep(context.Context, time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	f.calls++
	if f.calls == len(f.answers) {
		close(f.done)
	}
	if i < len(f.answers) {
		if err := f.answers[i]; err != nil {
			return 0, err
		}
		return 2, nil
	}
	return 0, nil
}

// The sweep runs at start and on each tick, logs what it deleted and a
// failure, and goes on after one.
func TestSweep(t *testing.T) {
	f := &fakeSweeper{answers: []error{nil, errors.New("the store is down"), nil}, done: make(chan struct{})}
	var logs syncBuffer
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		sweep(ctx, f, time.Hour, 5*time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
		close(stopped)
	}()
	<-f.done
	cancel()
	<-stopped
	out := logs.String()
	if strings.Count(out, "expired messages deleted") < 2 || !strings.Contains(out, "the store is down") {
		t.Errorf("the sweep logged:\n%s", out)
	}
}

// pinging is a store that answers a ping.
type pinging struct {
	store.Store
	err error
}

func (p pinging) Ping(context.Context) error { return p.err }

// Readiness asks a store that answers a ping, and takes one that does
// not as reachable.
func TestPing(t *testing.T) {
	down := errors.New("down")
	if err := ping(t.Context(), pinging{err: down}); !errors.Is(err, down) {
		t.Errorf("a store that is down: %v", err)
	}
	if err := ping(t.Context(), memory.New(time.Now)); err != nil {
		t.Errorf("the memory store: %v", err)
	}
}

// An issuer that is down at start delays sign-ins, not the server: it
// starts and says so.
func TestStartsWithTheIssuerDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := "http://" + ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	s := start(t, map[string]string{"SERMO_OIDC_ISSUERS": gone, "SERMO_ADDR": "127.0.0.1:0"})
	if code, _ := get(t, s.base+"/livez", ""); code != http.StatusOK {
		t.Errorf("/livez: %d", code)
	}
	s.stop(t)
	if !strings.Contains(s.output.String(), "an issuer's key set could not be read at start") {
		t.Errorf("the start said nothing of the issuer:\n%s", s.output.String())
	}
}
