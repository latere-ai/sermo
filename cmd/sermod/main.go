// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Command sermod is the Sermo server. It reads its SERMO_* settings,
// opens the store, the token verifier and the authorizer, and serves the
// messaging API with the probes beside it until it is stopped. This file
// holds wiring only; the behavior lives under internal/.
package main

import (
	"context"
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

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/health"
	"latere.ai/x/pkg/otel"

	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/config"
	"latere.ai/x/sermo/internal/version"
	sermo "latere.ai/x/sermo/server"
)

// Timing of a start and a stop. On a stop, readiness answers 503 at
// once, the drain delay lets a load balancer notice, and the server then
// closes within the grace period; a read waiting for messages ends when
// the stop begins.
const (
	drainDelay    = 3 * time.Second
	gracePeriod   = 30 * time.Second
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
	release := otel.Version(version.Version)
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, release)
		return 0
	}
	settings, err := config.FromEnv(getenv)
	if err != nil {
		return fail(stderr, err)
	}

	logger, flush, err := otel.Bootstrap(ctx, otel.Config{
		ServiceName: "sermod",
		Version:     release,
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
	defer srv.core.Close()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", settings.Addr)
	if err != nil {
		return fail(stderr, fmt.Errorf("SERMO_ADDR: %w", err))
	}
	_, _ = fmt.Fprintf(stdout, "sermod: %s listening on %s store=%s authorizer=%s\n", release, ln.Addr(), srv.core.StoreKind(), srv.authorizerKind)

	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		srv.core.Sweep(ctx, min(sweepEvery, settings.Retention/2))
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
	core           *sermo.Server
	handler        http.Handler
	stopping       *atomic.Bool
	authorizerKind string
}

// build opens the messaging server and mounts its API and the probes on
// one handler.
func build(ctx context.Context, s config.Settings, logger *slog.Logger) (*server, error) {
	client := &http.Client{Transport: otel.Transport(nil), Timeout: clientTimeout}
	authz, authorizerKind, err := openAuthorizer(ctx, s, client)
	if err != nil {
		return nil, err
	}
	core, err := sermo.New(ctx, sermo.Options{
		DatabaseURL:     s.DatabaseURL.Reveal(),
		DatabasePoolURL: s.DatabasePoolURL.Reveal(),
		Authorizer:      authz,
		OIDCIssuers:     s.OIDCIssuers,
		OIDCAudiences:   s.OIDCAudiences,
		ServiceKey:      s.ServiceKey.Private(),
		Installation:    s.InstallationKey,
		MaxRequestBytes: s.MaxRequestBytes,
		Retention:       s.Retention,
		HTTPClient:      client,
		Logger:          logger,
	})
	if err != nil {
		if errors.Is(err, sermo.ErrDatabase) {
			err = fmt.Errorf("SERMO_DATABASE_URL: %w", err)
		}
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
			health.Check{Name: "store", Run: core.Ping},
		),
		Timeout: readyTimeout,
		Version: otel.Version(version.Version),
	})
	mux := http.NewServeMux()
	mux.Handle(sermo.Prefix+"/", otel.Handler(core.Handler(), "sermo"))
	for _, path := range []string{"GET /livez", "GET /readyz", "GET /version"} {
		mux.Handle(path, probes)
	}
	// The build identity is also public below the API prefix, the one path
	// the ingress forwards, so a release check reads it from outside. It
	// takes no token and is the body /version serves.
	mux.Handle("GET "+sermo.Prefix+"/version", versionAt(probes))
	return &server{core: core, handler: mux, stopping: stopping, authorizerKind: authorizerKind}, nil
}

// versionAt serves the answer of the probes' /version at the path it is
// mounted on, so the build identity below the API prefix is the very body
// the root serves.
func versionAt(probes http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rooted := r.Clone(r.Context())
		rooted.URL.Path, rooted.URL.RawPath = "/version", ""
		probes.ServeHTTP(w, rooted)
	})
}

// openAuthorizer is the authorizer the settings name: the endpoint
// asked for every decision, which must refuse the probe every
// authorizer refuses before the server starts, or nil, the member
// policy in process, without one.
func openAuthorizer(ctx context.Context, s config.Settings, client *http.Client) (authz.Authorizer, string, error) {
	if s.AuthorizerURL == "" {
		return nil, "member policy", nil
	}
	remote, err := access.NewClient(s.AuthorizerURL, s.AuthorizerToken.Reveal(), client, time.Now)
	if err != nil {
		return nil, "", fmt.Errorf("SERMO_AUTHORIZER_URL: %w", err)
	}
	if err := access.Check(ctx, remote); err != nil {
		return nil, "", fmt.Errorf("SERMO_AUTHORIZER_URL: the authorizer failed the probe it must refuse: %w", err)
	}
	return remote, "remote", nil
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

func fail(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "sermod: %v\n", err)
	return 1
}
