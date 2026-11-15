// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"

	"latere.ai/x/sermo/server"
)

// A program runs Sermo beside its own routes: it builds the server, mounts
// the handler under the API prefix, and deletes expired messages in the
// background.
func Example_embed() {
	// A stand-in for the OpenID Connect issuer people sign in with.
	idp := httptest.NewUnstartedServer(nil)
	issuer := issuertest.NewHandler(issuertest.WithIssuer("http://" + idp.Listener.Addr().String()))
	idp.Config.Handler = issuer.Handler()
	idp.Start()
	defer idp.Close()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	s, err := server.New(ctx, server.Options{OIDCIssuers: []string{idp.URL}})
	if err != nil {
		panic(err)
	}
	defer s.Close()
	go s.Sweep(ctx, time.Hour)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /hello", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "hello") })
	mux.Handle(server.Prefix+"/", s.Handler())

	front := httptest.NewServer(mux)
	defer front.Close()
	for _, path := range []string{"/hello", server.Prefix + "/service"} {
		res, err := http.Get(front.URL + path)
		if err != nil {
			panic(err)
		}
		_ = res.Body.Close()
		fmt.Println(path, res.StatusCode)
	}
	// Output:
	// /hello 200
	// /v1/messaging/service 401
}
