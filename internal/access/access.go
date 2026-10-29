// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package access is who a caller is, and who decides what that caller
// may do (specs/003-identity-and-authorization.md).
//
// Who is a Verifier: a bearer is verified against one of the issuers
// SERMO_OIDC_ISSUERS lists, through latere.ai/x/pkg/authkit/jwt, and
// becomes a Caller with every claim of the token verbatim. No claim is
// read for meaning here.
//
// What is an Authorizer: one question per request, in the vocabulary of
// latere.ai/x/sermo/authorizer, goes to the endpoint SERMO_AUTHORIZER_URL
// names through the client of latere.ai/x/pkg/authz, which caches,
// retries and fails closed by that contract's rules. With no endpoint the
// member policy of this package answers.
package access

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"latere.ai/x/pkg/authkit/jwt"
	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/bearer"

	"latere.ai/x/sermo/authorizer"
)

// ClockSkew is how far an issuer's clock may differ from this server's.
const ClockSkew = 30 * time.Second

// Caller is a verified bearer. Subject is the issuer and the sub joined
// as authz renders them; Claims is every claim of the token, verbatim,
// handed to the authorizer and read by nothing in Sermo.
type Caller struct {
	Subject string
	Issuer  string
	Sub     string
	Claims  map[string]any
}

// The errors of a request's identity and question.
var (
	// ErrMissingToken is a request that carries no bearer.
	ErrMissingToken = errors.New("access: the request carries no bearer token")
	// ErrUnavailable is a question that got no decision; the request
	// fails closed.
	ErrUnavailable = errors.New("access: the authorizer gave no decision")
)

// TokenError is a bearer the verifier refused. Reason is the verifier's
// word for why, never a part of the token.
type TokenError struct {
	Reason string
	err    error
}

func (e *TokenError) Error() string { return "access: the bearer token was refused: " + e.Reason }

// Unwrap is the verifier's own error.
func (e *TokenError) Unwrap() error { return e.err }

// Verifier verifies a bearer against the listed issuers.
type Verifier struct {
	validator *jwt.Validator
}

// NewVerifier builds the verifier. It reads nothing from the network
// until a token arrives.
func NewVerifier(issuers, audiences []string, client *http.Client, now func() time.Time) (*Verifier, error) {
	if len(issuers) == 0 {
		return nil, errors.New("access: no issuer to verify callers against")
	}
	if len(audiences) == 0 || slices.Contains(audiences, "") {
		// A verifier with no audience would accept a token addressed to
		// any other service of the same issuer.
		return nil, errors.New("access: no audience to verify tokens for")
	}
	if client == nil {
		return nil, errors.New("access: no client to read key sets with")
	}
	trimmed := make([]string, len(issuers))
	for i, iss := range issuers {
		trimmed[i] = strings.TrimRight(iss, "/")
	}
	return &Verifier{validator: jwt.New(jwt.Config{
		Issuers: trimmed, Audiences: slices.Clone(audiences), HTTPClient: client,
		ClockSkew: ClockSkew, Now: now, ReadsGrants: true,
	})}, nil
}

// Warm reads every issuer's key set once.
func (v *Verifier) Warm(ctx context.Context) error { return v.validator.Warm(ctx) }

// Authenticate reads the bearer of a request and verifies it.
func (v *Verifier) Authenticate(r *http.Request) (Caller, error) {
	raw, ok := bearer.FromRequest(r)
	if !ok || raw == "" {
		return Caller{}, ErrMissingToken
	}
	verified, err := v.validator.Validate(raw)
	if err != nil {
		word := string(jwt.ReasonOf(err))
		if word == "" {
			word = "refused"
		}
		return Caller{}, &TokenError{Reason: word, err: err}
	}
	var claims map[string]any
	if err := jwt.DecodePayload(raw, &claims); err != nil {
		return Caller{}, &TokenError{Reason: string(jwt.ReasonMalformed), err: err}
	}
	issuer := strings.TrimRight(verified.Iss, "/")
	return Caller{Subject: authz.Subject(issuer, verified.Sub), Issuer: issuer, Sub: verified.Sub, Claims: claims}, nil
}

// Authenticator turns a request's bearer into a caller.
type Authenticator interface {
	Authenticate(r *http.Request) (Caller, error)
}

// Decision is the answer to a question.
type Decision struct {
	Allow bool
	// Reason is the authorizer's word, the developer detail of a deny.
	Reason string
}

// Authorizer answers one question about one caller. A deny is a
// Decision; an error wraps ErrUnavailable.
type Authorizer interface {
	Authorize(ctx context.Context, caller Caller, r *http.Request, action string, resource authz.Resource) (Decision, error)
}

// asker asks one authz.Authorizer: the shared client over the
// operator's endpoint, or the member policy.
type asker struct{ inner authz.Authorizer }

// NewAuthorizer wraps whichever authorizer a server runs.
func NewAuthorizer(inner authz.Authorizer) Authorizer { return &asker{inner: inner} }

// NewClient is the shared client over an operator's endpoint, with
// Sermo's vocabulary, so an action outside it costs no round trip.
func NewClient(url, token string, client *http.Client, now func() time.Time) (*authz.Client, error) {
	return authz.NewClient(authz.Options{URL: url, Token: token, HTTP: client, Now: now, Vocabulary: authorizer.Vocabulary()})
}

func (a *asker) Authorize(ctx context.Context, c Caller, r *http.Request, action string, res authz.Resource) (Decision, error) {
	// A question about another kind than its action acts on is a mistake
	// in a handler, refused before it can be answered with an allow.
	if kind := authorizer.Kind(action); kind == "" || kind != res.Kind {
		return Decision{}, fmt.Errorf("access: the action %q does not act on the kind %q", action, res.Kind)
	}
	claims := c.Claims
	if claims == nil {
		claims = map[string]any{}
	}
	d, err := a.inner.Authorize(ctx, authz.Request{
		Subject: c.Subject, Issuer: c.Issuer, Sub: c.Sub, Claims: claims,
		Action: action, Resource: res, Request: requestInfo(r),
	})
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %s: %w", ErrUnavailable, action, err)
	}
	if !d.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "no reason given"
		}
		return Decision{Reason: reason}, nil
	}
	return Decision{Allow: true, Reason: d.Reason}, nil
}

// requestInfo is what the authorizer is told about the request.
func requestInfo(r *http.Request) authz.Caller {
	if r == nil {
		return authz.Caller{}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return authz.Caller{ID: r.Header.Get("X-Request-Id"), IP: host, UserAgent: r.UserAgent()}
}

// Check sends the probe every authorizer denies and reports one that
// answered nothing or allowed it.
func Check(ctx context.Context, a authz.Authorizer) error {
	return authz.Check(ctx, a, authorizer.ActionConversationRead, authorizer.KindConversation)
}
