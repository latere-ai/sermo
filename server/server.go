// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package server runs Sermo inside another Go program. Use it when the
// messaging API should sit behind your own router, listener, probes and
// authorizer instead of in a separate sermod process: build a [Server]
// with [New], mount [Server.Handler] under [Prefix], and run
// [Server.Sweep] in a goroutine to delete expired messages.
//
// The server verifies the caller's OpenID Connect token itself and asks
// the [authz.Authorizer] you pass, or the built-in member policy where
// you pass none, who may reach whom. Everything else, the listener, the
// health probes and telemetry, stays with the caller. The sermod command
// is built on this package.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/otel"

	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/config"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
	"latere.ai/x/sermo/internal/store/postgres"
)

// Prefix is the path the API is served under. Handler answers only
// paths below it, so a caller mounts it at Prefix + "/".
const Prefix = httpapi.Prefix

// ErrDatabase is what New's error wraps when the database could not be
// opened or migrated.
var ErrDatabase = errors.New("server: opening the database")

// Timing of a start.
const (
	// warmTimeout bounds reading the issuers' key sets at start.
	warmTimeout = 10 * time.Second
	// openTimeout bounds opening the database and running its migrations.
	openTimeout = time.Minute
	// clientTimeout bounds each request of the default HTTP client.
	clientTimeout = 10 * time.Second
	// defaultSweepEvery is the interval of Sweep when none is given.
	defaultSweepEvery = time.Hour
)

// Options configure a Server. Only OIDCIssuers is required; the rest
// have the defaults named on each field.
type Options struct {
	// DatabaseURL is the Postgres URL the server keeps its state in. Empty
	// selects the memory store, which keeps nothing across a restart.
	DatabaseURL string
	// DatabasePoolURL is the URL of a transaction pooler in front of the
	// database, used for the server's queries while DatabaseURL runs the
	// migrations. Empty uses DatabaseURL for both. It needs a DatabaseURL.
	DatabasePoolURL string

	// Authorizer decides who may reach whom. Nil selects the member
	// policy, which needs no service.
	Authorizer authz.Authorizer

	// OIDCIssuers are the issuer URLs whose tokens are accepted.
	OIDCIssuers []string
	// OIDCAudiences are the audiences a token must name one of. Empty
	// accepts the default audience, "sermo".
	OIDCAudiences []string

	// ServiceKey is the Ed25519 key the server signs as the external
	// sender of every group. It is required with a DatabaseURL, because a
	// key made on each start would orphan every stored group. Nil with
	// the memory store generates one.
	ServiceKey ed25519.PrivateKey
	// Installation is the Ed25519 public key that attests the assistant's
	// member. Nil admits none.
	Installation ed25519.PublicKey

	// MaxRequestBytes bounds a request body. Zero takes 8 MiB.
	MaxRequestBytes int64
	// Retention is how long a message is kept before Sweep deletes it.
	// Zero takes 30 days.
	Retention time.Duration

	// HTTPClient fetches issuers' key sets. Nil takes a client with a
	// 10 second timeout.
	HTTPClient *http.Client
	// Logger receives the server's logs. Nil takes slog.Default.
	Logger *slog.Logger
	// Now is the clock. Nil takes time.Now.
	Now func() time.Time
}

// Server is Sermo running in process. It is safe for concurrent use.
type Server struct {
	handler   http.Handler
	svc       *conv.Service
	store     store.Store
	storeKind string
	retention time.Duration
	logger    *slog.Logger
	closeFn   func()
}

// durable is a store kept in a database, closed when the server stops.
type durable interface {
	store.Store
	Close()
}

// openPostgres opens the Postgres store, running its migrations first; a
// test stands in for it.
var openPostgres = func(ctx context.Context, o postgres.Options) (durable, error) { return postgres.Open(ctx, o) }

// New opens the store, the token verifier and the authorizer, and builds
// the API. It returns once the database answers and its migrations have
// run. An issuer that is down is logged, not an error: its key set is read
// again on the first token. The caller closes the result with Close.
func New(ctx context.Context, o Options) (*Server, error) {
	if len(o.OIDCIssuers) == 0 {
		return nil, errors.New("server: OIDCIssuers is empty")
	}
	if o.DatabaseURL == "" && o.DatabasePoolURL != "" {
		return nil, errors.New("server: DatabasePoolURL needs a DatabaseURL")
	}
	if o.DatabaseURL != "" && o.ServiceKey == nil {
		return nil, errors.New("server: a DatabaseURL needs a ServiceKey, because a key made on each start would orphan every stored group")
	}
	key := o.ServiceKey
	if key == nil {
		// A server without a database keeps nothing across a restart, so
		// a key made here serves every group it will ever hold.
		var err error
		if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	if o.MaxRequestBytes == 0 {
		o.MaxRequestBytes = config.DefaultMaxRequestBytes
	}
	if o.Retention == 0 {
		o.Retention = config.DefaultRetention
	}
	if len(o.OIDCAudiences) == 0 {
		o.OIDCAudiences = []string{config.DefaultAudience}
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Transport: otel.Transport(nil), Timeout: clientTimeout}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}

	st, kind, closeStore, err := openStore(ctx, o)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			closeStore()
		}
	}()

	var authorizer access.Authorizer
	if o.Authorizer == nil {
		authorizer = access.NewAuthorizer(access.MemberPolicy{})
	} else {
		authorizer = access.NewAuthorizer(o.Authorizer)
	}
	verifier, err := access.NewVerifier(o.OIDCIssuers, o.OIDCAudiences, o.HTTPClient, o.Now)
	if err != nil {
		return nil, err
	}
	warm, cancel := context.WithTimeout(ctx, warmTimeout)
	defer cancel()
	if err := verifier.Warm(warm); err != nil {
		// The key sets are read again on the first token, so an issuer
		// that is down at start delays sign-ins, not the server.
		o.Logger.WarnContext(ctx, "an issuer's key set could not be read at start", "err", err)
	}

	svc, err := conv.New(conv.Options{Store: st, Authorizer: authorizer, ServiceKey: key, Installation: o.Installation, Now: o.Now})
	if err != nil {
		return nil, err
	}
	api, err := httpapi.New(httpapi.Options{Service: svc, Authenticator: verifier, MaxRequestBytes: o.MaxRequestBytes, Logger: o.Logger})
	if err != nil {
		return nil, err
	}
	ok = true
	return &Server{handler: api, svc: svc, store: st, storeKind: kind, retention: o.Retention, logger: o.Logger, closeFn: closeStore}, nil
}

// openStore opens the store the options name: Postgres for a database
// URL, and memory without one.
func openStore(ctx context.Context, o Options) (store.Store, string, func(), error) {
	if o.DatabaseURL == "" {
		return memory.New(o.Now), "memory", func() {}, nil
	}
	opening, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	st, err := openPostgres(opening, postgres.Options{URL: o.DatabaseURL, PoolURL: o.DatabasePoolURL})
	if err != nil {
		// The store's errors never carry the URL, whose password this
		// error would print.
		return nil, "", nil, fmt.Errorf("%w: %w", ErrDatabase, err)
	}
	return st, "postgres", st.Close, nil
}

// Handler is the messaging API, which answers the paths below Prefix and
// no others. It has no health probes and no telemetry; the caller wraps
// it as it does its own routes.
func (s *Server) Handler() http.Handler { return s.handler }

// Ping reports whether the store answers. The memory store always does.
func (s *Server) Ping(ctx context.Context) error {
	if p, ok := s.store.(interface{ Ping(context.Context) error }); ok {
		return p.Ping(ctx)
	}
	return nil
}

// StoreKind names the store in use: "postgres" or "memory".
func (s *Server) StoreKind() string { return s.storeKind }

// Sweep deletes the messages older than the retention at start and then
// every interval, until ctx is done; zero takes one hour. A failed sweep
// is logged and tried again at the next.
func (s *Server) Sweep(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = defaultSweepEvery
	}
	sweep(ctx, s.svc, s.retention, every, s.logger)
}

// Close releases the store. Call it after the handler has stopped
// serving, and after Sweep has returned.
func (s *Server) Close() { s.closeFn() }

// sweeper deletes what is past the retention.
type sweeper interface {
	Sweep(ctx context.Context, retention time.Duration) (int, error)
}

func sweep(ctx context.Context, s sweeper, retention, every time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		n, err := s.Sweep(ctx, retention)
		switch {
		case err != nil && ctx.Err() == nil:
			logger.ErrorContext(ctx, "the sweep of expired messages failed", "err", err)
		case n > 0:
			logger.InfoContext(ctx, "expired messages deleted", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
