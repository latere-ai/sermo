// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authkit/jwt"
	"latere.ai/x/pkg/authz"

	"latere.ai/x/sermo/internal/access"
)

// now is the one instant the issuer mints at and the verifier checks at,
// so expiry and skew are exact.
var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

// verifier is a verifier of tokens for sermo from one test issuer, named
// with a trailing slash as an operator may write it.
func verifier(t *testing.T) (*access.Verifier, *issuertest.Server) {
	t.Helper()
	issuer := issuertest.New(t, issuertest.WithDefaultAudience("sermo"), issuertest.WithClock(clock))
	v, err := access.NewVerifier([]string{issuer.URL() + "/"}, []string{"sermo"}, http.DefaultClient, clock)
	if err != nil {
		t.Fatal(err)
	}
	return v, issuer
}

// request is a request that carries the Authorization header given, or
// none when it is empty.
func request(authorization string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/conversations", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

// TestNewVerifierRefuses checks the verifiers that would accept too much
// or could never read a key set.
func TestNewVerifierRefuses(t *testing.T) {
	issuers := []string{"https://issuer.example"}
	cases := []struct {
		name      string
		issuers   []string
		audiences []string
		client    *http.Client
	}{
		{"no issuer", nil, []string{"sermo"}, http.DefaultClient},
		{"no audience", issuers, nil, http.DefaultClient},
		{"an empty audience", issuers, []string{"sermo", ""}, http.DefaultClient},
		{"no client", issuers, []string{"sermo"}, nil},
	}
	for _, c := range cases {
		if v, err := access.NewVerifier(c.issuers, c.audiences, c.client, nil); err == nil || v != nil {
			t.Errorf("%s: NewVerifier = %v, %v, want a refusal", c.name, v, err)
		}
	}
}

// TestAuthenticate checks that a valid bearer becomes a caller with its
// issuer as the token names it, without the trailing slash, the subject
// authz renders, and every claim verbatim, grants included.
func TestAuthenticate(t *testing.T) {
	v, issuer := verifier(t)
	grants := []any{map[string]any{"type": authz.GrantType, "actions": []any{"sermo:conversation.read"}}}
	token := issuer.Mint(issuertest.Claims{Sub: "person-a", Extra: map[string]any{
		"token_use": authz.TokenUsePAT, "authorization_details": grants, "device_hint": "phone",
	}})
	c, err := v.Authenticate(request("Bearer " + token))
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != issuer.URL() || c.Sub != "person-a" || c.Subject != authz.Subject(issuer.URL(), "person-a") {
		t.Errorf("caller = %+v, want person-a of %s", c, issuer.URL())
	}
	if c.Claims["sub"] != "person-a" || c.Claims["iss"] != issuer.URL() || c.Claims["device_hint"] != "phone" || c.Claims["token_use"] != authz.TokenUsePAT {
		t.Errorf("claims = %v, want every claim of the token", c.Claims)
	}
	if got, err := authz.ParseGrants(c.Claims); err != nil || len(got) != 1 || got[0].Actions[0] != "sermo:conversation.read" {
		t.Errorf("the grants did not arrive verbatim: %v, %v", got, err)
	}
	// The scheme is matched in any case, as RFC 9110 has it.
	if _, err := v.Authenticate(request("bearer " + token)); err != nil {
		t.Errorf("a lowercase scheme was refused: %v", err)
	}
}

// TestAuthenticateMissing checks that a request without a bearer is told
// so, apart from a bearer that was refused.
func TestAuthenticateMissing(t *testing.T) {
	v, _ := verifier(t)
	for _, h := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer   "} {
		if _, err := v.Authenticate(request(h)); !errors.Is(err, access.ErrMissingToken) {
			t.Errorf("Authorization %q: err = %v, want ErrMissingToken", h, err)
		}
	}
}

// forged is a token of person-a carrying the signature the issuer made
// for person-b's.
func forged(issuer *issuertest.Server) string {
	a := issuer.Mint(issuertest.Claims{Sub: "person-a"})
	b := issuer.Mint(issuertest.Claims{Sub: "person-b"})
	return a[:strings.LastIndexByte(a, '.')] + b[strings.LastIndexByte(b, '.'):]
}

// TestAuthenticateRefuses checks each kind of bad bearer: the error is a
// TokenError with the verifier's word for why, it unwraps to the
// verifier's own error, and it never carries the token.
func TestAuthenticateRefuses(t *testing.T) {
	v, issuer := verifier(t)
	other := issuertest.New(t, issuertest.WithDefaultAudience("sermo"), issuertest.WithClock(clock))
	cases := []struct {
		name   string
		token  string
		reason jwt.Reason
		cause  error
	}{
		{"not a token", "not.a.token", jwt.ReasonMalformed, jwt.ErrMalformedToken},
		{"another audience", issuer.Mint(issuertest.Claims{Aud: issuertest.StringList{"drive"}}), jwt.ReasonBadAudience, jwt.ErrInvalidAudience},
		{"another issuer", other.Mint(issuertest.Claims{}), jwt.ReasonBadIssuer, jwt.ErrInvalidIssuer},
		{"expired past the skew", issuer.Mint(issuertest.Claims{Exp: now.Add(-access.ClockSkew - time.Second).Unix()}), jwt.ReasonExpired, jwt.ErrTokenExpired},
		{"not valid until past the skew", issuer.Mint(issuertest.Claims{Nbf: now.Add(access.ClockSkew + time.Minute).Unix()}), jwt.ReasonNotYetValid, jwt.ErrTokenNotValidYet},
		{"no subject", issuer.Mint(issuertest.Claims{Omit: []string{"sub"}}), jwt.ReasonMalformed, jwt.ErrMalformedToken},
		{"a signature of other claims", forged(issuer), jwt.ReasonBadSignature, jwt.ErrInvalidSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Authenticate(request("Bearer " + c.token))
			var te *access.TokenError
			if !errors.As(err, &te) {
				t.Fatalf("err = %v, want a TokenError", err)
			}
			if te.Reason != string(c.reason) {
				t.Errorf("Reason = %q, want %q", te.Reason, c.reason)
			}
			if c.cause != nil && !errors.Is(err, c.cause) {
				t.Errorf("err = %v does not unwrap to %v", err, c.cause)
			}
			if !strings.Contains(te.Error(), te.Reason) || strings.Contains(te.Error(), c.token) {
				t.Errorf("Error() = %q, want the reason and never the token", te.Error())
			}
		})
	}
}

// TestAuthenticateSkew checks that a token just expired, or not valid
// for a few seconds yet, still verifies within ClockSkew.
func TestAuthenticateSkew(t *testing.T) {
	v, issuer := verifier(t)
	for _, c := range []issuertest.Claims{
		{Exp: now.Add(-access.ClockSkew + time.Second).Unix()},
		{Nbf: now.Add(access.ClockSkew - time.Second).Unix()},
	} {
		if _, err := v.Authenticate(request("Bearer " + issuer.Mint(c))); err != nil {
			t.Errorf("a token within the skew was refused: %v", err)
		}
	}
}

// TestWarm checks that Warm reads a reachable issuer's key set and
// reports one it cannot reach.
func TestWarm(t *testing.T) {
	v, _ := verifier(t)
	if err := v.Warm(context.Background()); err != nil {
		t.Errorf("Warm: %v", err)
	}
	gone := issuertest.New(t)
	url := gone.URL()
	gone.Close()
	cold, err := access.NewVerifier([]string{url}, []string{"sermo"}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cold.Warm(ctx); err == nil {
		t.Error("Warm reached an issuer that is gone")
	}
}
