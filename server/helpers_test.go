// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/sermo/internal/access"
)

// keys makes a service key and its public half.
func keys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// authzClient is a client of the stub authorizer, as an embedding program
// would pass in.
func authzClient(t *testing.T, s *stub.Server) authz.Authorizer {
	t.Helper()
	c, err := access.NewClient(s.URL(), s.Token(), http.DefaultClient, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
