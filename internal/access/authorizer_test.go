// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/access"
)

// recorder is an authorizer that gives one answer to every question and
// keeps each request it was asked.
type recorder struct {
	asked    []authz.Request
	decision authz.Decision
	err      error
}

func (r *recorder) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	r.asked = append(r.asked, req)
	return r.decision, r.err
}

// caller is person-a of the test issuer, with one claim beside the sub.
func caller() access.Caller {
	return access.Caller{
		Subject: authz.Subject(issuerURL, me), Issuer: issuerURL, Sub: me,
		Claims: map[string]any{"sub": me, "device_hint": "phone"},
	}
}

// conv1 is a conversation of person-a's.
var conv1 = authz.NewResource(authorizer.KindConversation, "conv-1", map[string]any{authorizer.FieldPeople: []string{me}})

// TestAuthorizerAsks checks what the inner authorizer is told: the
// caller's identity and claims as they came, the question, and the
// request's correlation id, address and agent.
func TestAuthorizerAsks(t *testing.T) {
	inner := &recorder{decision: authz.Decision{Allow: true, Reason: "member"}}
	r := httptest.NewRequest(http.MethodGet, "/v1/conversations/conv-1", nil)
	r.RemoteAddr = "192.0.2.7:52100"
	r.Header.Set("X-Request-Id", "req-1")
	r.Header.Set("User-Agent", "sermo-test/1")
	d, err := access.NewAuthorizer(inner).Authorize(context.Background(), caller(), r, authorizer.ActionConversationRead, conv1)
	if err != nil {
		t.Fatal(err)
	}
	if d != (access.Decision{Allow: true, Reason: "member"}) {
		t.Errorf("decision = %+v, want the allow with its reason", d)
	}
	want := authz.Request{
		Subject: caller().Subject, Issuer: issuerURL, Sub: me, Claims: caller().Claims,
		Action: authorizer.ActionConversationRead, Resource: conv1,
		Request: authz.Caller{ID: "req-1", IP: "192.0.2.7", UserAgent: "sermo-test/1"},
	}
	if len(inner.asked) != 1 || !reflect.DeepEqual(inner.asked[0], want) {
		t.Errorf("asked %+v, want %+v", inner.asked, want)
	}
}

// TestAuthorizerRequestInfo checks the request facts when the address
// has no port and when there is no request at all, and that a caller
// with no claims is sent an empty object rather than none.
func TestAuthorizerRequestInfo(t *testing.T) {
	inner := &recorder{decision: authz.Decision{Allow: true}}
	a := access.NewAuthorizer(inner)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.8"
	c := caller()
	c.Claims = nil
	if _, err := a.Authorize(context.Background(), c, r, authorizer.ActionConversationRead, conv1); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authorize(context.Background(), c, nil, authorizer.ActionConversationRead, conv1); err != nil {
		t.Fatal(err)
	}
	if len(inner.asked) != 2 {
		t.Fatalf("asked %d times, want 2", len(inner.asked))
	}
	if got := inner.asked[0].Request.IP; got != "192.0.2.8" {
		t.Errorf("IP = %q, want the address as it came", got)
	}
	if got := inner.asked[1].Request; got != (authz.Caller{}) {
		t.Errorf("request facts without a request = %+v, want none", got)
	}
	for _, req := range inner.asked {
		if req.Claims == nil || len(req.Claims) != 0 {
			t.Errorf("claims = %v, want an empty object", req.Claims)
		}
	}
}

// TestAuthorizerAnswers checks how each answer of the inner authorizer
// comes back: a deny with its reason or a stated one, and an error as
// ErrUnavailable with its cause.
func TestAuthorizerAnswers(t *testing.T) {
	down := errors.New("connection refused")
	cases := []struct {
		name     string
		inner    recorder
		want     access.Decision
		wantErr  error
		wantDown bool
	}{
		{"a deny with a reason", recorder{decision: authz.Decision{Reason: "not_member"}}, access.Decision{Reason: "not_member"}, nil, false},
		{"a deny with none", recorder{decision: authz.Decision{}}, access.Decision{Reason: "no reason given"}, nil, false},
		{"an allow with none", recorder{decision: authz.Decision{Allow: true}}, access.Decision{Allow: true}, nil, false},
		{"no answer", recorder{err: down}, access.Decision{}, access.ErrUnavailable, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := access.NewAuthorizer(&c.inner).Authorize(context.Background(), caller(), nil, authorizer.ActionConversationRead, conv1)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if c.wantDown && !errors.Is(err, down) {
				t.Errorf("err = %v does not carry its cause", err)
			}
			if d != c.want {
				t.Errorf("decision = %+v, want %+v", d, c.want)
			}
		})
	}
}

// TestAuthorizerRefusesMismatch checks that a question about another
// kind than its action acts on, or about no action of the vocabulary, is
// an error before the inner authorizer could allow it.
func TestAuthorizerRefusesMismatch(t *testing.T) {
	inner := &recorder{decision: authz.Decision{Allow: true}}
	a := access.NewAuthorizer(inner)
	device := authz.NewResource(authorizer.KindDevice, "dev-1", nil)
	for _, q := range []struct {
		action string
		res    authz.Resource
	}{
		{authorizer.ActionConversationRead, device},
		{"conversation.delete", conv1},
	} {
		d, err := a.Authorize(context.Background(), caller(), nil, q.action, q.res)
		if err == nil || d.Allow {
			t.Errorf("%s on %s: decision %+v, err %v, want an error", q.action, q.res.Kind, d, err)
		}
		if errors.Is(err, access.ErrUnavailable) {
			t.Errorf("%s on %s: a mistake in a handler reads as an outage: %v", q.action, q.res.Kind, err)
		}
	}
	if len(inner.asked) != 0 {
		t.Errorf("the inner authorizer was asked %d times", len(inner.asked))
	}
}

// endpoint is a stub authorizer with Sermo's vocabulary that allows
// nobody unless a rule says so, and the client that asks it.
func endpoint(t *testing.T) (*stub.Server, *authz.Client) {
	t.Helper()
	s := stub.New(t, stub.WithToken(rand.Text()), stub.WithVocabulary(authorizer.Vocabulary()), stub.WithAllow())
	c, err := access.NewClient(s.URL(), s.Token(), http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

// TestClient checks the client over an operator's endpoint: an allow and
// a deny come back as the endpoint gave them, the endpoint is sent the
// caller's claims, and an endpoint that fails is ErrUnavailable.
func TestClient(t *testing.T) {
	s, c := endpoint(t)
	subject := caller().Subject
	s.Allow(stub.Rule{Subject: subject, Action: authorizer.ActionConversationRead, Resource: "conv-1"})
	s.Deny(stub.Rule{Subject: subject, Action: authorizer.ActionConversationRead, Resource: "conv-2"}, "not_member")
	a := access.NewAuthorizer(c)
	ctx := context.Background()
	read := authorizer.ActionConversationRead

	d, err := a.Authorize(ctx, caller(), nil, read, conv1)
	if err != nil || !d.Allow {
		t.Errorf("conv-1: decision %+v, err %v, want an allow", d, err)
	}
	conv2 := authz.NewResource(authorizer.KindConversation, "conv-2", nil)
	d, err = a.Authorize(ctx, caller(), nil, read, conv2)
	if err != nil || d.Allow || d.Reason != "not_member" {
		t.Errorf("conv-2: decision %+v, err %v, want a deny for not_member", d, err)
	}
	asked := s.Requests()
	if len(asked) != 2 || asked[0].Subject != subject || asked[0].Claims["device_hint"] != "phone" || asked[0].Resource.ID != "conv-1" {
		t.Errorf("the endpoint was asked %+v", asked)
	}

	s.Fail(http.StatusServiceUnavailable)
	conv3 := authz.NewResource(authorizer.KindConversation, "conv-3", nil)
	if d, err := a.Authorize(ctx, caller(), nil, read, conv3); !errors.Is(err, access.ErrUnavailable) || d.Allow {
		t.Errorf("a failing endpoint: decision %+v, err %v, want ErrUnavailable", d, err)
	}
}

// TestClientVocabulary checks that the client knows Sermo's actions, so
// one outside them is refused without a round trip.
func TestClientVocabulary(t *testing.T) {
	s, c := endpoint(t)
	_, err := c.Authorize(context.Background(), authz.Request{
		Subject: caller().Subject, Action: "conversation.delete", Resource: conv1,
	})
	var unknown *authz.UnknownAction
	if !errors.As(err, &unknown) {
		t.Errorf("err = %v, want an unknown action", err)
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("the endpoint was asked %d times", n)
	}
}

// TestNewClientRefuses checks that a client with no endpoint is refused
// when it is built, not at the first question.
func TestNewClientRefuses(t *testing.T) {
	if c, err := access.NewClient("", "token", http.DefaultClient, nil); err == nil || c != nil {
		t.Errorf("NewClient with no URL = %v, %v, want a refusal", c, err)
	}
}

// TestCheck checks the start-up probe: the member policy and a
// conforming endpoint deny it, and an authorizer that allows everything
// or answers nothing is reported.
func TestCheck(t *testing.T) {
	ctx := context.Background()
	_, c := endpoint(t)
	if err := access.Check(ctx, c); err != nil {
		t.Errorf("Check(endpoint) = %v", err)
	}
	if err := access.Check(ctx, access.MemberPolicy{}); err != nil {
		t.Errorf("Check(member policy) = %v", err)
	}
	if err := access.Check(ctx, &recorder{decision: authz.Decision{Allow: true}}); !errors.Is(err, authz.ErrProbeAllowed) {
		t.Errorf("Check(allows everything) = %v, want ErrProbeAllowed", err)
	}
	down := errors.New("connection refused")
	if err := access.Check(ctx, &recorder{err: down}); !errors.Is(err, down) {
		t.Errorf("Check(answers nothing) = %v, want its error", err)
	}
}
