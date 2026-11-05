// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package apierr_test

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/httpjson"

	"latere.ai/x/sermo/internal/apierr"
)

// every is each code the package declares, with the status the API spec
// gives it.
var every = map[string]int{
	apierr.CodeInvalid:               http.StatusBadRequest,
	apierr.CodeUnknownField:          http.StatusBadRequest,
	apierr.CodeMissingToken:          http.StatusUnauthorized,
	apierr.CodeInvalidToken:          http.StatusUnauthorized,
	apierr.CodeNotYourDevice:         http.StatusForbidden,
	apierr.CodeForbidden:             http.StatusForbidden,
	apierr.CodeNotFound:              http.StatusNotFound,
	apierr.CodeExists:                http.StatusConflict,
	apierr.CodeEpochTaken:            http.StatusConflict,
	apierr.CodeWrongEpoch:            http.StatusConflict,
	apierr.CodeRefused:               http.StatusUnprocessableEntity,
	apierr.CodeTooLarge:              http.StatusRequestEntityTooLarge,
	apierr.CodeAuthorizerUnavailable: http.StatusServiceUnavailable,
	apierr.CodeInternal:              http.StatusInternalServerError,
}

// TestTable checks that Codes lists every declared code once, and that
// each has its status and one sentence for a person: a full sentence,
// distinct from every other code's.
func TestTable(t *testing.T) {
	codes := apierr.Codes()
	slices.Sort(codes)
	if len(codes) != len(every) || len(slices.Compact(slices.Clone(codes))) != len(codes) {
		t.Fatalf("Codes = %q, want each of the %d declared codes once", codes, len(every))
	}
	messages := map[string]string{}
	for _, c := range codes {
		status, ok := every[c]
		if !ok {
			t.Errorf("Codes lists %q, which the package does not declare", c)
			continue
		}
		if got := apierr.Status(c); got != status {
			t.Errorf("Status(%q) = %d, want %d", c, got, status)
		}
		m := apierr.Message(c)
		if m == "" || !strings.HasSuffix(m, ".") || strings.ToUpper(m[:1]) != m[:1] {
			t.Errorf("Message(%q) = %q, want one sentence", c, m)
		}
		if other, dup := messages[m]; dup {
			t.Errorf("%q and %q share the message %q", c, other, m)
		}
		messages[m] = c
	}
}

// TestUnknownCode checks that a code the table lacks answers as a server
// fault with no sentence of its own, so a typo never reads as a client's
// mistake.
func TestUnknownCode(t *testing.T) {
	if got := apierr.Status("no_such_code"); got != http.StatusInternalServerError {
		t.Errorf("Status of an unknown code = %d, want 500", got)
	}
	if got := apierr.Message("no_such_code"); got != "" {
		t.Errorf("Message of an unknown code = %q, want none", got)
	}
}

// TestError checks the text of an error, with and without its detail,
// and what it unwraps to.
func TestError(t *testing.T) {
	cause := errors.New("the body ended early")
	cases := []struct {
		name  string
		err   *apierr.Error
		text  string
		cause error
	}{
		{"new with a detail", apierr.New(apierr.CodeInvalid, "no group info"), "invalid: no group info", nil},
		{"new without a detail", apierr.New(apierr.CodeForbidden, ""), "forbidden", nil},
		{"wrap", apierr.Wrap(apierr.CodeInvalid, cause), "invalid: the body ended early", cause},
		{"internal", apierr.Internal(cause), "internal", cause},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.err.Error(); got != c.text {
				t.Errorf("Error() = %q, want %q", got, c.text)
			}
			if got := c.err.Unwrap(); !errors.Is(got, c.cause) {
				t.Errorf("Unwrap() = %v, want %v", got, c.cause)
			}
			if c.cause != nil && !errors.Is(c.err, c.cause) {
				t.Error("errors.Is does not reach the cause")
			}
		})
	}
	if e := apierr.Wrap(apierr.CodeNotFound, cause); e.Code != apierr.CodeNotFound || e.Detail != cause.Error() {
		t.Errorf("Wrap = %+v, want the code and the cause's text as detail", e)
	}
	if e := apierr.Internal(cause); e.Code != apierr.CodeInternal || e.Detail != "" {
		t.Errorf("Internal = %+v, want the internal code and no detail", e)
	}
}

// TestClassify checks that an *Error is its own answer, also through a
// wrap, and that any other error is internal with its cause kept for the
// log.
func TestClassify(t *testing.T) {
	e := apierr.New(apierr.CodeNotFound, "no such conversation")
	if got := apierr.Classify(e); got != e {
		t.Errorf("Classify(*Error) = %v, want the error itself", got)
	}
	if got := apierr.Classify(fmt.Errorf("reading: %w", e)); got != e {
		t.Errorf("Classify(wrapped *Error) = %v, want the error inside", got)
	}
	plain := errors.New("disk full")
	got := apierr.Classify(plain)
	if got.Code != apierr.CodeInternal || got.Detail != "" || !errors.Is(got, plain) {
		t.Errorf("Classify(plain) = %+v, want internal with the cause kept", got)
	}
}

// TestWrite checks the response an error makes: its status, its code,
// its fixed sentence and its detail, and that an internal error says
// nothing of its cause.
func TestWrite(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
		detail string
	}{
		{"with a detail", apierr.New(apierr.CodeWrongEpoch, "the epoch is 4"), http.StatusConflict, apierr.CodeWrongEpoch, "the epoch is 4"},
		{"without a detail", apierr.New(apierr.CodeMissingToken, ""), http.StatusUnauthorized, apierr.CodeMissingToken, ""},
		{"wrapped", fmt.Errorf("handler: %w", apierr.New(apierr.CodeTooLarge, "over 8 MiB")), http.StatusRequestEntityTooLarge, apierr.CodeTooLarge, "over 8 MiB"},
		{"unclassified", errors.New("connection reset by the database at 10.0.0.7"), http.StatusInternalServerError, apierr.CodeInternal, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			e := apierr.Write(rec, c.err)
			if e.Code != c.code {
				t.Errorf("Write returned %q, want %q", e.Code, c.code)
			}
			if rec.Code != c.status {
				t.Errorf("status = %d, want %d", rec.Code, c.status)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q", ct)
			}
			raw := rec.Body.String()
			var body httpjson.ErrorEnvelope
			if err := json.Unmarshal([]byte(raw), &body); err != nil {
				t.Fatalf("body %q: %v", raw, err)
			}
			if body.Error.Code != c.code || body.Error.Message != apierr.Message(c.code) {
				t.Errorf("body = %+v, want the code %q and its sentence", body.Error, c.code)
			}
			detail, hasDetail := body.Error.Details["detail"]
			if c.detail == "" && hasDetail {
				t.Errorf("details = %v, want none", body.Error.Details)
			}
			if c.detail != "" && detail != c.detail {
				t.Errorf("detail = %v, want %q", detail, c.detail)
			}
			if c.code == apierr.CodeInternal && strings.Contains(raw, "10.0.0.7") {
				t.Errorf("an internal error told the caller its cause: %s", raw)
			}
		})
	}
}
