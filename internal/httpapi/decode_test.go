// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/sermo/internal/apierr"
)

// TestDecodeRefusals checks the body decoder's answers: its code and
// the detail a person reads.
func TestDecodeRefusals(t *testing.T) {
	for _, c := range []struct {
		name, body, code, detail string
	}{
		{"one value", `{"id":"x"}`, "", ""},
		{"an empty body", ``, apierr.CodeInvalid, "the body is empty"},
		{"a blank body", " \n", apierr.CodeInvalid, "the body is empty"},
		{"an unknown member", `{"id":"x","extra":1}`, apierr.CodeUnknownField, `unknown field "extra"`},
		{"a second value", `{"id":"x"} {}`, apierr.CodeInvalid, "the body holds more than one JSON value"},
		{"trailing text", `{"id":"x"} x`, apierr.CodeInvalid, ""},
		{"a truncated value", `{"id":`, apierr.CodeInvalid, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(c.body))
			var v struct {
				ID string `json:"id"`
			}
			err := decode(r, &v)
			if c.code == "" {
				if err != nil || v.ID != "x" {
					t.Fatalf("decode = %v, %+v", err, v)
				}
				return
			}
			var e *apierr.Error
			if !errors.As(err, &e) || e.Code != c.code || (c.detail != "" && e.Detail != c.detail) {
				t.Fatalf("decode = %v, want %s %q", err, c.code, c.detail)
			}
		})
	}
}

// TestNextOmittedWhenZero checks that a backup page leaves out a zero
// cursor and writes a set one.
func TestNextOmittedWhenZero(t *testing.T) {
	zero, err := json.Marshal(BackupList{Records: []StoredBackupRecord{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(zero) != `{"records":[]}` {
		t.Fatalf("a list with no cursor = %s", zero)
	}
	set, err := json.Marshal(BackupList{Records: []StoredBackupRecord{}, Next: 4})
	if err != nil {
		t.Fatal(err)
	}
	if string(set) != `{"records":[],"next":4}` {
		t.Fatalf("a list with a cursor = %s", set)
	}
}
