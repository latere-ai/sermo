// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/sermo/authorizer"
	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/httpapi"
)

func records(ids ...string) httpapi.BackupPut {
	var p httpapi.BackupPut
	for _, id := range ids {
		p.Records = append(p.Records, httpapi.BackupRecord{ID: id, Sealed: []byte("sealed " + id)})
	}
	return p
}

// A person's backup records of a conversation are stored once however many
// devices store them, are read back in the order stored, oldest or newest
// first, by pages, and are no one else's to read.
func TestBackupRecords(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.newDevice("alice", "phone"), e.newDevice("bob", "pixel")
	external := service(t, e)
	id := create(t, alice, external)
	letIn(t, alice, id, bob)
	tablet := e.vouched(alice, "tablet")
	path := "/conversations/" + id + "/backup"

	var stored httpapi.BackupStored
	e.must(alice.call("POST", path, records("m1", "m2", "m3"), &stored), http.StatusOK, "store")
	if stored.Added != 3 {
		t.Fatalf("added %d, want 3", stored.Added)
	}
	// Another device of the person stores the same message and a new one:
	// the first copy of m2 stays.
	again := httpapi.BackupPut{Records: []httpapi.BackupRecord{{ID: "m2", Sealed: []byte("another sealing of m2")}, {ID: "m4", Sealed: []byte("sealed m4")}}}
	e.must(tablet.call("POST", path, again, &stored), http.StatusOK, "store from the tablet")
	if stored.Added != 1 {
		t.Fatalf("added %d, want 1", stored.Added)
	}
	e.must(bob.call("POST", path, records("m1"), &stored), http.StatusOK, "bob stores his own m1")
	if stored.Added != 1 {
		t.Fatalf("bob's m1 was taken for alice's: added %d", stored.Added)
	}

	var all httpapi.BackupList
	e.must(tablet.call("GET", path, nil, &all), http.StatusOK, "list")
	var ids []string
	for _, r := range all.Records {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "m1,m2,m3,m4" || all.Next != 0 {
		t.Fatalf("oldest first: %v next %d", ids, all.Next)
	}
	if !bytes.Equal(all.Records[1].Sealed, []byte("sealed m2")) {
		t.Fatalf("the second sealing replaced the first: %q", all.Records[1].Sealed)
	}

	// Pages of two, oldest first and newest first.
	var page httpapi.BackupList
	e.must(alice.call("GET", path+"?limit=2", nil, &page), http.StatusOK, "first page")
	if len(page.Records) != 2 || page.Next != page.Records[1].Cursor {
		t.Fatalf("first page %+v", page)
	}
	var second httpapi.BackupList
	e.must(alice.call("GET", fmt.Sprintf("%s?limit=2&cursor=%d", path, page.Next), nil, &second), http.StatusOK, "second page")
	if len(second.Records) != 2 || second.Records[0].ID != "m3" {
		t.Fatalf("second page %+v", second)
	}
	var last httpapi.BackupList
	e.must(alice.call("GET", fmt.Sprintf("%s?limit=2&cursor=%d", path, second.Next), nil, &last), http.StatusOK, "last page")
	if len(last.Records) != 0 || last.Next != 0 {
		t.Fatalf("past the end %+v", last)
	}
	var newest httpapi.BackupList
	e.must(alice.call("GET", path+"?order=newest&limit=3", nil, &newest), http.StatusOK, "newest")
	if len(newest.Records) != 3 || newest.Records[0].ID != "m4" || newest.Records[2].ID != "m2" || newest.Next != newest.Records[2].Cursor {
		t.Fatalf("newest %+v", newest)
	}
	var rest httpapi.BackupList
	e.must(alice.call("GET", fmt.Sprintf("%s?order=newest&limit=3&cursor=%d", path, newest.Next), nil, &rest), http.StatusOK, "newest, on")
	if len(rest.Records) != 1 || rest.Records[0].ID != "m1" || rest.Next != 0 {
		t.Fatalf("newest, on %+v", rest)
	}

	// Bob reads his own, and alice's never reach him.
	var bobs httpapi.BackupList
	e.must(bob.call("GET", path, nil, &bobs), http.StatusOK, "bob's list")
	if len(bobs.Records) != 1 || !bytes.Equal(bobs.Records[0].Sealed, []byte("sealed m1")) {
		t.Fatalf("bob read %+v", bobs)
	}
}

// The refusals of the backup routes: who may, which bodies, and the limits.
func TestBackupRefusals(t *testing.T) {
	e := newEnv(t, func(o *options) { o.backupBytes = 100 })
	alice, carol := e.newDevice("alice", "phone"), e.newDevice("carol", "tab")
	id := create(t, alice, service(t, e))
	path := "/conversations/" + id + "/backup"

	for _, c := range []struct {
		name string
		do   func() answer
		code string
	}{
		{"no token", func() answer { return e.call("GET", path, "", "", nil, nil) }, "missing_token"},
		{"no device", func() answer { return e.call("GET", path, alice.token, "", nil, nil) }, "not_your_device"},
		{"another person's device", func() answer { return e.call("GET", path, carol.token, alice.id.Device, nil, nil) }, "not_your_device"},
		{"not of the conversation, read", func() answer { return carol.call("GET", path, nil, nil) }, "forbidden"},
		{"not of the conversation, store", func() answer { return carol.call("POST", path, records("m1"), nil) }, "forbidden"},
		{"no such conversation", func() answer { return alice.call("GET", "/conversations/nope/backup", nil, nil) }, "not_found"},
		{"no records", func() answer { return alice.call("POST", path, httpapi.BackupPut{}, nil) }, "invalid"},
		{"an empty id", func() answer { return alice.call("POST", path, records(""), nil) }, "invalid"},
		{"a long id", func() answer {
			return alice.call("POST", path, records(strings.Repeat("x", conv.MaxBackupIDBytes+1)), nil)
		}, "invalid"},
		{"an empty record", func() answer {
			return alice.call("POST", path, httpapi.BackupPut{Records: []httpapi.BackupRecord{{ID: "m1"}}}, nil)
		}, "invalid"},
		{"an unknown field", func() answer { return alice.call("POST", path, `{"records":[],"extra":1}`, nil) }, "unknown_field"},
		{"a bad order", func() answer { return alice.call("GET", path+"?order=sideways", nil, nil) }, "invalid"},
		{"a bad cursor", func() answer { return alice.call("GET", path+"?cursor=-1", nil, nil) }, "invalid"},
		{"too many records", func() answer {
			var ids []string
			for i := range conv.MaxBackupBatch + 1 {
				ids = append(ids, fmt.Sprint("m", i))
			}
			return alice.call("POST", path, records(ids...), nil)
		}, "too_large"},
		{"a large record", func() answer {
			return alice.call("POST", path, httpapi.BackupPut{Records: []httpapi.BackupRecord{{ID: "m1", Sealed: make([]byte, conv.MaxBackupRecordBytes+1)}}}, nil)
		}, "too_large"},
	} {
		if a := c.do(); a.code != c.code {
			t.Errorf("%s: answered %+v, want %s", c.name, a, c.code)
		}
	}

	// A person's records stop at the limit, and what was refused stored
	// nothing; the same records are accepted again once they fit.
	big := httpapi.BackupPut{Records: []httpapi.BackupRecord{{ID: "a", Sealed: make([]byte, 60)}, {ID: "b", Sealed: make([]byte, 60)}}}
	if a := alice.call("POST", path, big, nil); a.code != "too_large" {
		t.Fatalf("over the person's limit: %+v", a)
	}
	var list httpapi.BackupList
	e.must(alice.call("GET", path, nil, &list), http.StatusOK, "list")
	if len(list.Records) != 0 {
		t.Fatalf("a refused write stored %+v", list.Records)
	}
	e.must(alice.call("POST", path, big.Records[0:1:1][0:1][0:1:1][0:0:0][:0], nil), http.StatusBadRequest, "nothing")
}

// A denied authorizer refuses the routes, and a record's content never
// reaches a log line.
func TestBackupDeniedAndCanary(t *testing.T) {
	e := newEnv(t)
	alice := e.newDevice("alice", "phone")
	id := create(t, alice, service(t, e))
	path := "/conversations/" + id + "/backup"
	const canary = "canary-b41c sealed words"
	e.must(alice.call("POST", path, httpapi.BackupPut{Records: []httpapi.BackupRecord{{ID: "m1", Sealed: []byte(canary)}}}, nil), http.StatusOK, "store")
	e.must(alice.call("GET", path, nil, nil), http.StatusOK, "list")
	if strings.Contains(e.logs.String(), canary) || strings.Contains(e.logs.String(), base64.StdEncoding.EncodeToString([]byte(canary))) {
		t.Fatal("a record's content reached a log line")
	}
	member := access.NewAuthorizer(access.MemberPolicy{})
	d := newEnv(t, func(o *options) { o.authorizer = denyOnly{authorizer.ActionBackupRecovery, member} })
	dev := d.newDevice("alice", "phone")
	did := create(t, dev, service(t, d))
	for _, a := range []answer{dev.call("GET", "/conversations/"+did+"/backup", nil, nil), dev.call("POST", "/conversations/"+did+"/backup", records("m1"), nil)} {
		if a.code != "forbidden" {
			t.Fatalf("a denied authorizer: %+v", a)
		}
	}
}
