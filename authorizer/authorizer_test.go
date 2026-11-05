// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authorizer_test

import (
	"bufio"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/sermo/authorizer"
)

// specRow is one row of the vocabulary table of spec 003.
type specRow struct {
	kind, action string
	fields       []string
	id           bool
}

func specTable(t *testing.T) []specRow {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "specs", "003-identity-and-authorization.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	row := regexp.MustCompile("^\\| `([A-Za-z]+)` \\| `([a-z_]+\\.[a-z_]+)` \\| (.*) \\|$")
	word := regexp.MustCompile("`([a-z_]+)`")
	var rows []specRow
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		m := row.FindStringSubmatch(scan.Text())
		if m == nil {
			continue
		}
		r := specRow{kind: m[1], action: m[2]}
		for _, w := range word.FindAllStringSubmatch(m[3], -1) {
			if w[1] == "id" {
				r.id = true
			} else {
				r.fields = append(r.fields, w[1])
			}
		}
		rows = append(rows, r)
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

// The package is the vocabulary table of spec 003, in its order, with its
// fields.
func TestTheVocabularyIsTheSpecs(t *testing.T) {
	rows := specTable(t)
	if len(rows) == 0 {
		t.Fatal("no row of the vocabulary table was read")
	}
	actions := authorizer.Actions()
	if len(actions) != len(rows) {
		t.Fatalf("the package has %d actions and the spec %d", len(actions), len(rows))
	}
	v := authorizer.Vocabulary()
	if v.Core != authorizer.Core || len(v.Actions) != len(rows) {
		t.Fatalf("the vocabulary is %+v", v)
	}
	for i, r := range rows {
		if actions[i] != r.action {
			t.Errorf("row %d: the package has %q and the spec %q", i, actions[i], r.action)
		}
		if got := authorizer.Kind(r.action); got != r.kind {
			t.Errorf("%s acts on %q, the spec says %q", r.action, got, r.kind)
		}
		if !authorizer.Known(r.action) {
			t.Errorf("%s is not known", r.action)
		}
		if got := authorizer.Fields(r.action); !slices.Equal(got, r.fields) {
			t.Errorf("%s sends %v, the spec says %v", r.action, got, r.fields)
		}
		if got := authorizer.SendsID(r.action); got != r.id {
			t.Errorf("%s sends an id: %v, the spec says %v", r.action, got, r.id)
		}
	}
	if authorizer.Known("conversation.steal") || authorizer.Kind("conversation.steal") != "" || authorizer.Fields("x") != nil || authorizer.SendsID("x") {
		t.Error("a string outside the table is an action")
	}
	if v.Label(authorizer.KindKeyPackage) != "Key packages" {
		t.Error("the kinds carry no label")
	}
}

// The envelope keeps kind and id for the resource itself, so no field
// takes either name.
func TestNoFieldTakesANameTheEnvelopeKeeps(t *testing.T) {
	for _, action := range authorizer.Actions() {
		for _, f := range authorizer.Fields(action) {
			if f == "kind" || f == "id" {
				t.Errorf("%s sends a field named %q", action, f)
			}
		}
	}
}

// A question with every field of its action set survives the wire.
func TestEveryFieldSurvivesTheWire(t *testing.T) {
	for _, action := range authorizer.Actions() {
		fields := map[string]any{}
		for _, f := range authorizer.Fields(action) {
			fields[f] = "the " + f
		}
		for _, list := range []string{authorizer.FieldPeople, authorizer.FieldOwners, authorizer.FieldChanges,
			authorizer.FieldAddPeople, authorizer.FieldRemovePeople, authorizer.FieldNewOwners} {
			if _, ok := fields[list]; ok {
				fields[list] = []any{"https://issuer.example.com|alice", "https://issuer.example.com|bob"}
			}
		}
		id := ""
		if authorizer.SendsID(action) {
			id = "C0NV"
		}
		sent := authz.Request{
			Subject: "https://issuer.example.com|alice", Issuer: "https://issuer.example.com", Sub: "alice",
			Action: action, Resource: authz.NewResource(authorizer.Kind(action), id, fields),
		}
		raw, err := json.Marshal(sent)
		if err != nil {
			t.Fatal(err)
		}
		var got authz.Request
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if got.Action != action || got.Resource.Kind != authorizer.Kind(action) || got.Resource.ID != id {
			t.Errorf("%s arrived as %s on %q %q", action, got.Action, got.Resource.Kind, got.Resource.ID)
		}
		for name, want := range fields {
			if v, ok := got.Resource.Fields[name]; !ok || !reflect.DeepEqual(v, want) {
				t.Errorf("%s: %s arrived as %v, %v", action, name, v, ok)
			}
		}
	}
}
