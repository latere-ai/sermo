// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Command sermod is the Sermo server. It reads its SERMO_* settings,
// opens the store, the token verifier and the authorizer, and serves the
// messaging API with the probes beside it until it is stopped. This file
// holds wiring only; the behavior lives under internal/.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"latere.ai/x/pkg/health"
	"latere.ai/x/pkg/otel"

	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/config"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
	"latere.ai/x/sermo/internal/store/memory"
	"latere.ai/x/sermo/internal/store/postgres"
)

// Timing of a start and a stop. On a stop, readiness answers 503 at
// once, the drain delay lets a load balancer notice, and the server then
// closes within the grace period; a read waiting for messages ends when
// the stop begins.
const (
	drainDelay  = 3 * time.Second
	gracePeriod = 30 * time.Second
	warmTimeout = 10 * time.Second
	// openTimeout bounds opening the database and running its
	// migrations at start.
	openTimeout   = time.Minute
	clientTimeout = 10 * time.Second
	readyTimeout  = 2 * time.Second
	flushTimeout  = 5 * time.Second
	// sweepEvery is how often expired messages are deleted, at most.
	sweepEvery = time.Hour
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// options are what a test changes about a run.
type options struct {
	drain time.Duration
}

// run serves until ctx is done and returns the exit code: 0 on a clean
// stop, 1 on a failure to start or serve, 2 on a usage error.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	return runWith(ctx, args, getenv, stdout, stderr, options{drain: drainDelay})
}

func runWith(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, o options) int {
	fs := flag.NewFlagSet("sermod", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "sermod: takes no arguments; it reads its settings from SERMO_* variables")
		return 2
	}
	version := otel.Version("")
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	}
	settings, err := config.FromEnv(getenv)
	if err != nil {
		return fail(stderr, err)
	}

	logger, flush, err := otel.Bootstrap(ctx, otel.Config{
		ServiceName: "sermod",
		Version:     version,
		Stdout:      slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}),
	})
	if err != nil {
		// The OTLP log bridge is degraded and the local path is not, so
		// the server serves and says so.
		logger.WarnContext(ctx, "the OTLP log bridge is degraded; logging stays local", "err", err)
	}
	defer func() {
		done, cancel := context.WithTimeout(context.WithoutCancel(ctx), flushTimeout)
		defer cancel()
		if err := flush(done); err != nil {
			logger.WarnContext(done, "telemetry did not flush", "err", err)
		}
	}()

	srv, err := build(ctx, settings, logger)
	if err != nil {
		return fail(stderr, err)
	}
	defer srv.close()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", settings.Addr)
	if err != nil {
		return fail(stderr, fmt.Errorf("SERMO_ADDR: %w", err))
	}
	_, _ = fmt.Fprintf(stdout, "sermod: %s listening on %s store=%s authorizer=%s\n", version, ln.Addr(), srv.storeKind, srv.authorizerKind)

	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		sweep(ctx, srv.svc, settings.Retention, min(sweepEvery, settings.Retention/2), logger)
	}()
	err = serve(ctx, ln, srv, o.drain, logger)
	<-sweepDone
	if err != nil {
		return fail(stderr, err)
	}
	return 0
}

// server is what one run serves.
type server struct {
	svc            *conv.Service
	handler        http.Handler
	stopping       *atomic.Bool
	storeKind      string
	authorizerKind string
	close          func()
}

// build opens the store, the verifier and the authorizer, and mounts the
// API and the probes on one handler.
func build(ctx context.Context, s config.Settings, logger *slog.Logger) (*server, error) {
	key := s.ServiceKey.Private()
	if key == nil {
		// A server without a database keeps nothing across a restart, so
		// a key made here serves every group it will ever hold.
		var err error
		if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	st, storeKind, closeStore, err := openStore(ctx, s)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			closeStore()
		}
	}()

	client := &http.Client{Transport: otel.Transport(nil), Timeout: clientTimeout}
	authz, authorizerKind, err := openAuthorizer(ctx, s, client)
	if err != nil {
		return nil, err
	}
	verifier, err := access.NewVerifier(s.OIDCIssuers, s.OIDCAudiences, client, time.Now)
	if err != nil {
		return nil, err
	}
	warm, cancel := context.WithTimeout(ctx, warmTimeout)
	defer cancel()
	if err := verifier.Warm(warm); err != nil {
		// The key sets are read again on the first token, so an issuer
		// that is down at start delays sign-ins, not the server.
		logger.WarnContext(ctx, "an issuer's key set could not be read at start", "err", err)
	}

	svc, err := conv.New(conv.Options{Store: st, Authorizer: authz, ServiceKey: key, Installation: s.InstallationKey})
	if err != nil {
		return nil, err
	}
	api, err := httpapi.New(httpapi.Options{Service: svc, Authenticator: verifier, MaxRequestBytes: s.MaxRequestBytes, Logger: logger})
	if err != nil {
		return nil, err
	}
	stopping := &atomic.Bool{}
	probes := health.Handler(health.Options{
		Ready: health.Checks(
			health.Check{Name: "stopping", Run: func(context.Context) error {
				if stopping.Load() {
					return errors.New("the server is stopping")
				}
				return nil
			}},
			health.Check{Name: "store", Run: func(ctx context.Context) error { return ping(ctx, st) }},
		),
		Timeout: readyTimeout,
		Version: otel.Version(""),
	})
	mux := http.NewServeMux()
	mux.Handle(httpapi.Prefix+"/", otel.Handler(api, "sermo"))
	for _, path := range []string{"GET /livez", "GET /readyz", "GET /version"} {
		mux.Handle(path, probes)
	}
	ok = true
	return &server{svc: svc, handler: mux, stopping: stopping, storeKind: storeKind, authorizerKind: authorizerKind, close: closeStore}, nil
}

// durable is a store kept in a database, closed when the server stops.
type durable interface {
	store.Store
	Close()
}

// openPostgres opens the Postgres store, running its migrations first; a
// test stands in for it.
var openPostgres = func(ctx context.Context, o postgres.Options) (durable, error) { return postgres.Open(ctx, o) }

// openStore opens the store the settings name: Postgres for a database
// URL, and memory, which keeps nothing across a restart, without one.
func openStore(ctx context.Context, s config.Settings) (store.Store, string, func(), error) {
	if !s.Durable() {
		return memory.New(time.Now), "memory", func() {}, nil
	}
	opening, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	st, err := openPostgres(opening, postgres.Options{URL: s.DatabaseURL.Reveal(), PoolURL: s.DatabasePoolURL.Reveal()})
	if err != nil {
		// The store's errors never carry the URL, whose password this
		// line would print.
		return nil, "", nil, fmt.Errorf("SERMO_DATABASE_URL: %w", err)
	}
	return st, "postgres", st.Close, nil
}

// ping asks a store that can answer whether it is reachable; one that
// cannot, the memory store, always is.
func ping(ctx context.Context, st store.Store) error {
	if p, ok := st.(interface{ Ping(context.Context) error }); ok {
		return p.Ping(ctx)
	}
	return nil
}

// openAuthorizer is the authorizer the settings name: the endpoint
// asked for every decision, which must refuse the probe every
// authorizer refuses before the server starts, or the member policy in
// process without one.
func openAuthorizer(ctx context.Context, s config.Settings, client *http.Client) (access.Authorizer, string, error) {
	if s.AuthorizerURL == "" {
		return access.NewAuthorizer(access.MemberPolicy{}), "member policy", nil
	}
	remote, err := access.NewClient(s.AuthorizerURL, s.AuthorizerToken.Reveal(), client, time.Now)
	if err != nil {
		return nil, "", fmt.Errorf("SERMO_AUTHORIZER_URL: %w", err)
	}
	if err := access.Check(ctx, remote); err != nil {
		return nil, "", fmt.Errorf("SERMO_AUTHORIZER_URL: the authorizer failed the probe it must refuse: %w", err)
	}
	return access.NewAuthorizer(remote), "remote", nil
}

// serve serves on ln until ctx is done, then stops: readiness fails,
// the drain delay passes, waiting reads end, and the server closes
// within the grace period.
func serve(ctx context.Context, ln net.Listener, srv *server, drain time.Duration, logger *slog.Logger) error {
	requests, endRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer endRequests()
	hs := &http.Server{
		Handler:           srv.handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return requests },
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() {
		err := hs.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
	}()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	srv.stopping.Store(true)
	logger.InfoContext(context.WithoutCancel(ctx), "stopping", "drain", drain.String())
	time.Sleep(drain)
	endRequests()
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), gracePeriod)
	defer cancel()
	return errors.Join(hs.Shutdown(stop), <-served)
}

// sweeper deletes what is past the retention.
type sweeper interface {
	Sweep(ctx context.Context, retention time.Duration) (int, error)
}

// sweep deletes expired messages at start and then every interval until
// ctx is done. A failed sweep is logged and tried again at the next.
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

func fail(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "sermod: %v\n", err)
	return 1
}
