// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authz/stub"
	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
	"latere.ai/x/sermo/internal/store/postgres"
)

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

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func request(t *testing.T, h http.Handler, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func register(t *testing.T, h http.Handler, token, person, device string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := messaging.NewDeviceRecord(person, device, priv, enc.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if code, b := request(t, h, http.MethodPut, Prefix+"/devices/"+device, token, body); code != http.StatusNoContent {
		t.Fatalf("registering a device: %d %s", code, b)
	}
}

// A server with the memory store and the member policy serves a signed-in
// person end to end, and refuses a request with no token.
func TestMemoryServesARequest(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	s, err := New(t.Context(), Options{OIDCIssuers: []string{iss.URL()}, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if s.StoreKind() != "memory" {
		t.Errorf("StoreKind = %q", s.StoreKind())
	}
	if err := s.Ping(t.Context()); err != nil {
		t.Errorf("Ping on the memory store: %v", err)
	}
	h := s.Handler()
	if code, _ := request(t, h, http.MethodGet, Prefix+"/people/alice/devices", "", nil); code != http.StatusUnauthorized {
		t.Errorf("a request with no token: %d", code)
	}
	token := iss.Mint(issuertest.Claims{Sub: "alice"})
	register(t, h, token, "alice", "phone")
	code, b := request(t, h, http.MethodGet, Prefix+"/people/alice/devices", token, nil)
	var list httpapi.DeviceList
	if code != http.StatusOK || json.Unmarshal(b, &list) != nil || len(list.Records) != 1 {
		t.Fatalf("the directory: %d %s", code, b)
	}
	// The handler answers below the prefix only: it brings no probes.
	if code, _ := request(t, h, http.MethodGet, "/livez", "", nil); code != http.StatusNotFound {
		t.Errorf("/livez: %d, want 404", code)
	}
}

// The authorizer passed in is the one asked: a person it allows can be
// reached, and one it does not know is refused.
func TestAuthorizerIsAsked(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	az := stub.New(t, stub.WithVocabulary(authorizer.Vocabulary()), stub.WithAllow(iss.URL()+"|alice"))
	remote := authzClient(t, az)
	key, _ := keys(t)
	s, err := New(t.Context(), Options{OIDCIssuers: []string{iss.URL()}, Authorizer: remote, ServiceKey: key, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	alice := iss.Mint(issuertest.Claims{Sub: "alice"})
	if code, b := request(t, s.Handler(), http.MethodGet, Prefix+"/people/alice/devices", alice, nil); code != http.StatusOK {
		t.Errorf("a person the authorizer allows: %d %s", code, b)
	}
	bob := iss.Mint(issuertest.Claims{Sub: "bob"})
	if code, _ := request(t, s.Handler(), http.MethodGet, Prefix+"/people/bob/devices", bob, nil); code == http.StatusOK {
		t.Error("a person the authorizer does not know was served")
	}
	az.Fail(http.StatusInternalServerError)
	if code, _ := request(t, s.Handler(), http.MethodGet, Prefix+"/people/alice/devices", alice, nil); code == http.StatusOK {
		t.Error("a failing authorizer did not fail the request closed")
	}
}

// The service key the caller passes is the one the server signs with.
func TestServiceKeyIsTheCallers(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	key, _ := keys(t)
	s, err := New(t.Context(), Options{OIDCIssuers: []string{iss.URL()}, ServiceKey: key, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	code, b := request(t, s.Handler(), http.MethodGet, Prefix+"/service", iss.Mint(issuertest.Claims{Sub: "alice"}), nil)
	var service httpapi.Service
	if code != http.StatusOK || json.Unmarshal(b, &service) != nil || !bytes.Equal(service.ExternalSender.SignatureKey, key.Public().(ed25519.PublicKey)) {
		t.Errorf("the service names another key: %d %s", code, b)
	}
}

// What New refuses to start with, and the database that is never opened
// for it.
func TestNewRefuses(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	was := openPostgres
	openPostgres = func(context.Context, postgres.Options) (durable, error) {
		t.Error("the database was opened for options New refuses")
		return nil, errors.New("opened")
	}
	t.Cleanup(func() { openPostgres = was })
	key, _ := keys(t)
	for name, c := range map[string]struct {
		o    Options
		want string
	}{
		"a database with no service key": {Options{OIDCIssuers: []string{iss.URL()}, DatabaseURL: "postgres://db.example/sermo"}, "ServiceKey"},
		"no issuer":                      {Options{}, "OIDCIssuers"},
		"a pool URL with no database":    {Options{OIDCIssuers: []string{iss.URL()}, DatabasePoolURL: "postgres://pool.example/sermo", ServiceKey: key}, "DatabasePoolURL"},
	} {
		c.o.Logger = quiet()
		s, err := New(t.Context(), c.o)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %s", name, err, c.want)
		}
		if s != nil {
			s.Close()
		}
	}
}

// closing is a store kept in a database, with what the server did to it.
type closing struct {
	store.Store
	pings, closes atomic.Int32
	err           error
}

func (c *closing) Ping(context.Context) error { c.pings.Add(1); return c.err }
func (c *closing) Close()                     { c.closes.Add(1) }

// A database URL opens the Postgres store with both endpoints the
// options name; Ping asks it and Close closes it once. A store that
// cannot be opened is an ErrDatabase that never carries the URL.
func TestDurableStore(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	key, _ := keys(t)
	db := &closing{Store: memory.New(time.Now)}
	var opened postgres.Options
	was := openPostgres
	t.Cleanup(func() { openPostgres = was })
	openPostgres = func(_ context.Context, o postgres.Options) (durable, error) { opened = o; return db, nil }
	o := Options{OIDCIssuers: []string{iss.URL()}, ServiceKey: key, Logger: quiet(),
		DatabaseURL: "postgres://direct.example/sermo", DatabasePoolURL: "postgres://pooled.example/sermo"}
	s, err := New(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if s.StoreKind() != "postgres" {
		t.Errorf("StoreKind = %q", s.StoreKind())
	}
	if opened.URL != "postgres://direct.example/sermo" || opened.PoolURL != "postgres://pooled.example/sermo" {
		t.Errorf("opened %+v", opened)
	}
	down := errors.New("down")
	db.err = down
	if err := s.Ping(t.Context()); !errors.Is(err, down) || db.pings.Load() != 1 {
		t.Errorf("Ping: %v after %d pings", err, db.pings.Load())
	}
	s.Close()
	if n := db.closes.Load(); n != 1 {
		t.Errorf("the store was closed %d times", n)
	}

	openPostgres = func(context.Context, postgres.Options) (durable, error) {
		return nil, errors.New("connection refused")
	}
	_, err = New(t.Context(), o)
	if !errors.Is(err, ErrDatabase) {
		t.Errorf("a database that does not open: %v", err)
	}
}

// A store that fails after it opened is closed, not leaked, when New
// fails later.
func TestNewClosesTheStoreOnFailure(t *testing.T) {
	key, _ := keys(t)
	db := &closing{Store: memory.New(time.Now)}
	was := openPostgres
	t.Cleanup(func() { openPostgres = was })
	openPostgres = func(context.Context, postgres.Options) (durable, error) { return db, nil }
	// An empty audience, which the verifier refuses.
	_, err := New(t.Context(), Options{OIDCIssuers: []string{"http://127.0.0.1:1"}, OIDCAudiences: []string{""}, ServiceKey: key, Logger: quiet(), DatabaseURL: "postgres://db.example/sermo"})
	if err == nil {
		t.Fatal("an empty audience was accepted")
	}
	if db.closes.Load() != 1 {
		t.Errorf("the store was closed %d times after a failed New", db.closes.Load())
	}
}

// An issuer that is down at start delays sign-ins, not the server: New
// succeeds and says so.
func TestIssuerDownAtStart(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := "http://" + ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	var logs syncBuffer
	s, err := New(t.Context(), Options{OIDCIssuers: []string{gone}, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if !strings.Contains(logs.String(), "an issuer's key set could not be read at start") {
		t.Errorf("New said nothing of the issuer:\n%s", logs.String())
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

// Server.Sweep blocks until its context is done, and returns at once
// when it already is.
func TestServerSweepStopsWithItsContext(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithDefaultAudience("sermo"))
	s, err := New(t.Context(), Options{OIDCIssuers: []string{iss.URL()}, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { s.Sweep(ctx, 0); close(done) }()
	select {
	case <-done:
		t.Fatal("Sweep returned before its context was done")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Sweep did not stop with its context")
	}
}
