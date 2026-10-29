// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"latere.ai/x/pkg/httpjson"
	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/api"
	"latere.ai/x/sermo/internal/apierr"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/httpapi"
	"latere.ai/x/sermo/internal/store"
)

// document is the part of api/openapi.yaml these tests read. It is decoded
// strictly, so a key the model lacks, such as a misspelled `requred`, fails
// the decode instead of being dropped unread.
type document struct {
	OpenAPI    string                           `yaml:"openapi"`
	Info       docInfo                          `yaml:"info"`
	Servers    []docServer                      `yaml:"servers"`
	Security   []map[string][]string            `yaml:"security"`
	Tags       []docTag                         `yaml:"tags"`
	Paths      map[string]map[string]*operation `yaml:"paths"`
	Components components                       `yaml:"components"`
}

type docInfo struct {
	Title       string `yaml:"title"`
	Summary     string `yaml:"summary"`
	Description string `yaml:"description"`
	Version     string `yaml:"version"`
	License     struct {
		Name       string `yaml:"name"`
		Identifier string `yaml:"identifier"`
	} `yaml:"license"`
}

type docServer struct {
	URL         string `yaml:"url"`
	Description string `yaml:"description"`
}

type docTag struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type operation struct {
	OperationID string               `yaml:"operationId"`
	Tags        []string             `yaml:"tags"`
	Summary     string               `yaml:"summary"`
	Description string               `yaml:"description"`
	Parameters  []*parameter         `yaml:"parameters"`
	RequestBody *requestBody         `yaml:"requestBody"`
	Responses   map[string]*response `yaml:"responses"`
	// Security is nil when the operation keeps the document's.
	Security *[]map[string][]string `yaml:"security"`
}

type parameter struct {
	Ref         string  `yaml:"$ref"`
	Name        string  `yaml:"name"`
	In          string  `yaml:"in"`
	Required    bool    `yaml:"required"`
	Description string  `yaml:"description"`
	Schema      *schema `yaml:"schema"`
}

type requestBody struct {
	Required bool              `yaml:"required"`
	Content  map[string]*media `yaml:"content"`
}

type response struct {
	Ref         string            `yaml:"$ref"`
	Description string            `yaml:"description"`
	Content     map[string]*media `yaml:"content"`
}

type media struct {
	Schema *schema `yaml:"schema"`
}

type schema struct {
	Ref                  string             `yaml:"$ref"`
	Type                 string             `yaml:"type"`
	Format               string             `yaml:"format"`
	ContentEncoding      string             `yaml:"contentEncoding"`
	Description          string             `yaml:"description"`
	Enum                 []string           `yaml:"enum"`
	Properties           map[string]*schema `yaml:"properties"`
	Required             []string           `yaml:"required"`
	AdditionalProperties *bool              `yaml:"additionalProperties"`
	Items                *schema            `yaml:"items"`
	AllOf                []*schema          `yaml:"allOf"`
	Minimum              *int64             `yaml:"minimum"`
	Maximum              *int64             `yaml:"maximum"`
	MaxItems             *int               `yaml:"maxItems"`
	Default              any                `yaml:"default"`
}

type components struct {
	SecuritySchemes map[string]*securityScheme `yaml:"securitySchemes"`
	Parameters      map[string]*parameter      `yaml:"parameters"`
	Responses       map[string]*response       `yaml:"responses"`
	Schemas         map[string]*schema         `yaml:"schemas"`
}

type securityScheme struct {
	Type         string `yaml:"type"`
	Scheme       string `yaml:"scheme"`
	BearerFormat string `yaml:"bearerFormat"`
	Description  string `yaml:"description"`
}

var parsed = sync.OnceValues(func() (*document, error) {
	var d document
	if err := yaml.UnmarshalWithOptions(api.Document, &d, yaml.Strict()); err != nil {
		return nil, err
	}
	return &d, nil
})

// loadDocument is api/openapi.yaml, parsed once for every test.
func loadDocument(t testing.TB) *document {
	t.Helper()
	d, err := parsed()
	if err != nil {
		t.Fatalf("api/openapi.yaml does not parse: %v", err)
	}
	if d.OpenAPI != "3.1.0" || len(d.Paths) == 0 {
		t.Fatalf("api/openapi.yaml is OpenAPI %q with %d paths", d.OpenAPI, len(d.Paths))
	}
	return d
}

// operations lists every operation as "METHOD path".
func (d *document) operations() map[string]*operation {
	out := map[string]*operation{}
	for path, item := range d.Paths {
		for method, op := range item {
			out[strings.ToUpper(method)+" "+path] = op
		}
	}
	return out
}

func (d *document) byID(id string) *operation {
	for _, op := range d.operations() {
		if op.OperationID == id {
			return op
		}
	}
	return nil
}

func (d *document) parameter(p *parameter) *parameter {
	if p.Ref == "" {
		return p
	}
	name, ok := strings.CutPrefix(p.Ref, "#/components/parameters/")
	if !ok {
		return nil
	}
	return d.Components.Parameters[name]
}

// response is the response a status of an operation answers with, its
// reference followed.
func (d *document) response(r *response) *response {
	if r.Ref == "" {
		return r
	}
	name, ok := strings.CutPrefix(r.Ref, "#/components/responses/")
	if !ok {
		return nil
	}
	return d.Components.Responses[name]
}

func (d *document) schemaAt(ref string) (string, *schema) {
	name, ok := strings.CutPrefix(ref, "#/components/schemas/")
	if !ok {
		return "", nil
	}
	return name, d.Components.Schemas[name]
}

// codes are the error codes a refusal answers with: the `error.code` enum
// its schema narrows the error envelope to.
func (d *document) codes(r *response) ([]string, error) {
	r = d.response(r)
	if r == nil {
		return nil, fmt.Errorf("the response refers to no component")
	}
	m := r.Content["application/json"]
	if m == nil || m.Schema == nil || len(m.Schema.AllOf) != 2 || m.Schema.AllOf[0].Ref != "#/components/schemas/Error" {
		return nil, fmt.Errorf("the response is not the error envelope narrowed to its codes")
	}
	e := m.Schema.AllOf[1].Properties["error"]
	if e == nil || e.Properties["code"] == nil || len(e.Properties["code"].Enum) == 0 {
		return nil, fmt.Errorf("the response names no error.code")
	}
	return e.Properties["code"].Enum, nil
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// TestTheDocumentAndTheRoutesAgree reads both ways: a route the server
// registers with no operation in the document, and an operation the server
// does not serve, each fail here.
func TestTheDocumentAndTheRoutesAgree(t *testing.T) {
	d := loadDocument(t)
	served := map[string]bool{}
	for _, r := range httpapi.Routes() {
		key := r.Method + " " + r.Pattern
		if served[key] {
			t.Errorf("the server registers %s twice", key)
		}
		served[key] = true
	}
	if len(served) == 0 {
		t.Fatal("the server registers no route, so this test would pass vacuously")
	}
	described := d.operations()
	for route := range served {
		if described[route] == nil {
			t.Errorf("the server serves %s and api/openapi.yaml describes no operation for it", route)
		}
	}
	for route := range described {
		if !served[route] {
			t.Errorf("api/openapi.yaml describes %s and the server serves no such route", route)
		}
	}
}

// placeholder is one path parameter of a path template.
var placeholder = regexp.MustCompile(`\{([^}]+)\}`)

// TestEveryOperationIsDescribed holds each operation to what a developer
// reads: an id, a summary, a description and a tag; a parameter, with a
// type, for every placeholder of its path; and the device header, required
// where the route speaks for a device.
func TestEveryOperationIsDescribed(t *testing.T) {
	d := loadDocument(t)
	routes := map[string]httpapi.Route{}
	for _, r := range httpapi.Routes() {
		routes[r.Method+" "+r.Pattern] = r
	}
	tags := map[string]bool{}
	for _, tag := range d.Tags {
		if tag.Description == "" {
			t.Errorf("the tag %q has no description", tag.Name)
		}
		tags[tag.Name] = true
	}
	ids := map[string]string{}
	for where, op := range d.operations() {
		if op.OperationID == "" {
			t.Errorf("%s has no operationId", where)
		} else if other, ok := ids[op.OperationID]; ok {
			t.Errorf("%s and %s share the operationId %q", where, other, op.OperationID)
		}
		ids[op.OperationID] = where
		if op.Summary == "" || strings.HasSuffix(op.Summary, ".") {
			t.Errorf("%s: the summary %q is not a short phrase", where, op.Summary)
		}
		if op.Description == "" {
			t.Errorf("%s has no description", where)
		}
		if len(op.Tags) == 0 {
			t.Errorf("%s has no tag", where)
		}
		for _, tag := range op.Tags {
			if !tags[tag] {
				t.Errorf("%s names the tag %q, which the document does not declare", where, tag)
			}
		}
		var inPath []string
		var device *parameter
		for _, ref := range op.Parameters {
			p := d.parameter(ref)
			if p == nil {
				t.Errorf("%s: the parameter %s refers to nothing", where, ref.Ref)
				continue
			}
			if p.Schema == nil || p.Schema.Type == "" {
				t.Errorf("%s: the parameter %q states no type in its schema", where, p.Name)
			}
			if p.Description == "" {
				t.Errorf("%s: the parameter %q has no description", where, p.Name)
			}
			switch {
			case p.In == "path":
				if !p.Required {
					t.Errorf("%s: the path parameter %q is not required", where, p.Name)
				}
				inPath = append(inPath, p.Name)
			case p.In == "header" && p.Name == httpapi.DeviceHeader:
				device = p
			}
		}
		_, path, _ := strings.Cut(where, " ")
		var placeholders []string
		for _, m := range placeholder.FindAllStringSubmatch(path, -1) {
			placeholders = append(placeholders, m[1])
		}
		if !sameSet(inPath, placeholders) {
			t.Errorf("%s describes the path parameters %v, and its path has %v", where, inPath, placeholders)
		}
		r, ok := routes[where]
		switch {
		case !ok:
		case device == nil:
			t.Errorf("%s does not describe the %s header", where, httpapi.DeviceHeader)
		case device.Required != r.Device:
			t.Errorf("%s: %s is required %t, and the route speaks for a device: %t", where, httpapi.DeviceHeader, device.Required, r.Device)
		}
	}
	if len(ids) != len(routes) {
		t.Errorf("the document has %d operations and the server %d routes", len(ids), len(routes))
	}
}

// TestSecurityIsDeclared: every route needs a bearer token from the
// operator's issuer, which the document declares once and no operation
// sets aside.
func TestSecurityIsDeclared(t *testing.T) {
	d := loadDocument(t)
	if len(d.Components.SecuritySchemes) != 1 {
		t.Errorf("the document declares %d security schemes, want the one bearer", len(d.Components.SecuritySchemes))
	}
	s := d.Components.SecuritySchemes["bearer"]
	if s == nil || s.Type != "http" || s.Scheme != "bearer" || !strings.Contains(s.Description, "OpenID Connect") {
		t.Errorf("the bearer scheme is %+v, want an http bearer from the operator's OpenID Connect issuer", s)
	}
	if len(d.Security) != 1 || len(d.Security[0]) != 1 || d.Security[0]["bearer"] == nil {
		t.Errorf("the document's security is %v, want the bearer on every operation", d.Security)
	}
	for where, op := range d.operations() {
		if op.Security != nil {
			t.Errorf("%s sets the document's security aside, and the server needs a token on every route", where)
		}
		if op.Responses["401"] == nil {
			t.Errorf("%s does not describe the refusal of a missing or refused token", where)
		}
	}
}

// TestTheDocumentNamesNoInstallation: the document travels to every reader
// of this open core, so the one server it names is an example, and it
// carries no host of anyone's and no reference to this repository's insides.
func TestTheDocumentNamesNoInstallation(t *testing.T) {
	const example = "https://sermo.example"
	d := loadDocument(t)
	if len(d.Servers) != 1 || d.Servers[0].URL != example {
		t.Errorf("the document names the servers %+v, want the example alone", d.Servers)
	}
	body := strings.ToLower(strings.ReplaceAll(string(api.Document), example, ""))
	for _, s := range []string{"http://", "https://", "latere.ai", "specs/", "internal/"} {
		if strings.Contains(body, s) {
			t.Errorf("the document names %q", s)
		}
	}
}

// The Go type of each schema of the document.
var schemaTypes = map[string]reflect.Type{
	"Bytes":              reflect.TypeFor[[]byte](),
	"Error":              reflect.TypeFor[httpjson.ErrorEnvelope](),
	"ErrorBody":          reflect.TypeFor[httpjson.Error](),
	"ErrorCode":          reflect.TypeFor[string](),
	"Service":            reflect.TypeFor[httpapi.Service](),
	"ExternalSender":     reflect.TypeFor[httpapi.ExternalSender](),
	"RecordKind":         reflect.TypeFor[messaging.RecordKind](),
	"DeviceRecord":       reflect.TypeFor[messaging.DeviceRecord](),
	"Revocation":         reflect.TypeFor[messaging.Revocation](),
	"DeviceList":         reflect.TypeFor[httpapi.DeviceList](),
	"Recovery":           reflect.TypeFor[httpapi.RecoveryBody](),
	"Transfer":           reflect.TypeFor[httpapi.TransferBody](),
	"KeyPackagePublish":  reflect.TypeFor[httpapi.KeyPackagesBody](),
	"KeyPackageCount":    reflect.TypeFor[httpapi.KeyPackageCount](),
	"KeyPackageClaim":    reflect.TypeFor[httpapi.ClaimBody](),
	"ClaimedKeyPackage":  reflect.TypeFor[httpapi.ClaimedKeyPackage](),
	"ClaimedKeyPackages": reflect.TypeFor[httpapi.ClaimedList](),
	"ConversationKind":   reflect.TypeFor[messaging.Kind](),
	"Level":              reflect.TypeFor[messaging.Level](),
	"ConversationCreate": reflect.TypeFor[httpapi.CreateBody](),
	"Conversation":       reflect.TypeFor[httpapi.Conversation](),
	"ConversationList":   reflect.TypeFor[httpapi.ConversationList](),
	"GroupInfo":          reflect.TypeFor[httpapi.GroupInfoBody](),
	"MessageSend":        reflect.TypeFor[httpapi.SendBody](),
	"MessageKind":        reflect.TypeFor[store.MessageKind](),
	"MessageSent":        reflect.TypeFor[httpapi.Sent](),
	"Message":            reflect.TypeFor[httpapi.Message](),
	"MessageList":        reflect.TypeFor[httpapi.MessageList](),
	"Welcome":            reflect.TypeFor[httpapi.Welcome](),
	"WelcomeList":        reflect.TypeFor[httpapi.WelcomeList](),
	"Membership":         reflect.TypeFor[httpapi.Membership](),
}

// stringEnums are the values of the string types whose values reflection
// cannot list.
var stringEnums = map[reflect.Type][]string{
	reflect.TypeFor[store.MessageKind](): {string(store.KindApplication), string(store.KindProposal), string(store.KindCommit)},
}

// body is what one route reads and answers: the Go type of its request
// body, nil for none, its success status, and the Go type of its answer,
// nil for none.
type body struct {
	in     reflect.Type
	status int
	out    reflect.Type
}

var bodies = map[string]body{
	"GET " + httpapi.Prefix + "/service":                            {nil, http.StatusOK, reflect.TypeFor[httpapi.Service]()},
	"GET " + httpapi.Prefix + "/people/{person}/devices":            {nil, http.StatusOK, reflect.TypeFor[httpapi.DeviceList]()},
	"PUT " + httpapi.Prefix + "/devices/{device}":                   {reflect.TypeFor[messaging.DeviceRecord](), http.StatusNoContent, nil},
	"POST " + httpapi.Prefix + "/revocations":                       {reflect.TypeFor[messaging.Revocation](), http.StatusNoContent, nil},
	"PUT " + httpapi.Prefix + "/recovery":                           {reflect.TypeFor[httpapi.RecoveryBody](), http.StatusNoContent, nil},
	"GET " + httpapi.Prefix + "/recovery":                           {nil, http.StatusOK, reflect.TypeFor[httpapi.RecoveryBody]()},
	"POST " + httpapi.Prefix + "/devices/{device}/transfer":         {reflect.TypeFor[httpapi.TransferBody](), http.StatusNoContent, nil},
	"GET " + httpapi.Prefix + "/devices/{device}/transfer":          {nil, http.StatusOK, reflect.TypeFor[httpapi.TransferBody]()},
	"POST " + httpapi.Prefix + "/key-packages":                      {reflect.TypeFor[httpapi.KeyPackagesBody](), http.StatusNoContent, nil},
	"GET " + httpapi.Prefix + "/key-packages":                       {nil, http.StatusOK, reflect.TypeFor[httpapi.KeyPackageCount]()},
	"POST " + httpapi.Prefix + "/key-packages/claim":                {reflect.TypeFor[httpapi.ClaimBody](), http.StatusOK, reflect.TypeFor[httpapi.ClaimedList]()},
	"POST " + httpapi.Prefix + "/conversations":                     {reflect.TypeFor[httpapi.CreateBody](), http.StatusCreated, reflect.TypeFor[httpapi.Conversation]()},
	"GET " + httpapi.Prefix + "/conversations":                      {nil, http.StatusOK, reflect.TypeFor[httpapi.ConversationList]()},
	"GET " + httpapi.Prefix + "/conversations/{id}":                 {nil, http.StatusOK, reflect.TypeFor[httpapi.Conversation]()},
	"GET " + httpapi.Prefix + "/conversations/{id}/group-info":      {nil, http.StatusOK, reflect.TypeFor[httpapi.GroupInfoBody]()},
	"POST " + httpapi.Prefix + "/conversations/{id}/messages":       {reflect.TypeFor[httpapi.SendBody](), http.StatusCreated, reflect.TypeFor[httpapi.Sent]()},
	"GET " + httpapi.Prefix + "/conversations/{id}/messages":        {nil, http.StatusOK, reflect.TypeFor[httpapi.MessageList]()},
	"GET " + httpapi.Prefix + "/welcomes":                           {nil, http.StatusOK, reflect.TypeFor[httpapi.WelcomeList]()},
	"DELETE " + httpapi.Prefix + "/welcomes/{id}":                   {nil, http.StatusNoContent, nil},
	"GET " + httpapi.Prefix + "/conversations/{id}/people/{person}": {nil, http.StatusOK, reflect.TypeFor[httpapi.Membership]()},
}

var (
	bytesType = reflect.TypeFor[[]byte]()
	timeType  = reflect.TypeFor[time.Time]()
	textType  = reflect.TypeFor[encoding.TextMarshaler]()
)

// jsonField is one member of a struct as encoding/json writes it.
type jsonField struct {
	name      string
	typ       reflect.Type
	omitempty bool
}

func jsonFields(t reflect.Type) []jsonField {
	var out []jsonField
	for f := range t.Fields() {
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		switch {
		case !f.IsExported() || name == "-":
			continue
		case f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct:
			out = append(out, jsonFields(f.Type)...)
			continue
		case name == "":
			name = f.Name
		}
		out = append(out, jsonField{name: name, typ: f.Type, omitempty: slices.Contains(strings.Split(opts, ","), "omitempty")})
	}
	return out
}

// texts is every value a one-byte enum's MarshalText accepts.
func texts(t reflect.Type) []string {
	var out []string
	for i := range 256 {
		v := reflect.New(t).Elem()
		v.SetUint(uint64(i))
		m, ok := reflect.TypeAssert[encoding.TextMarshaler](v)
		if !ok {
			return nil
		}
		if b, err := m.MarshalText(); err == nil {
			out = append(out, string(b))
		}
	}
	return out
}

// checker compares schemas to the Go types they describe.
type checker struct {
	t *testing.T
	d *document
	// seen is every schema compared, by name and by whether a request
	// carries it, so a schema reached twice is compared once.
	seen map[string]bool
}

func (c *checker) compare(where string, s *schema, t reflect.Type, request bool) {
	c.t.Helper()
	if s == nil {
		c.t.Errorf("%s: no schema describes the Go type %s", where, t)
		return
	}
	if s.Ref != "" {
		name, target := c.d.schemaAt(s.Ref)
		want, known := schemaTypes[name]
		switch {
		case target == nil || !known:
			c.t.Errorf("%s refers to %s, which is no schema of the Go types", where, s.Ref)
			return
		case want != t:
			c.t.Errorf("%s refers to %s, which is the Go type %s, and the server has %s there", where, name, want, t)
			return
		}
		key := name + " " + strconv.FormatBool(request)
		if !c.seen[key] {
			c.seen[key] = true
			c.compare("components.schemas."+name, target, t, request)
		}
		return
	}
	want := func(typ, format string) {
		c.t.Helper()
		if s.Type != typ || (format != "" && s.Format != format) {
			c.t.Errorf("%s is type %q format %q, and encoding/json writes the Go type %s as %s %s", where, s.Type, s.Format, t, typ, format)
		}
	}
	switch k := t.Kind(); {
	case t == bytesType:
		want("string", "")
		if s.ContentEncoding != "base64" {
			c.t.Errorf("%s is bytes, which encoding/json writes in base64, and its contentEncoding is %q", where, s.ContentEncoding)
		}
	case t == timeType:
		want("string", "date-time")
	case k == reflect.Uint8 && t.Implements(textType):
		want("string", "")
		if !sameSet(s.Enum, texts(t)) {
			c.t.Errorf("%s lists %v, and the Go type %s writes %v", where, s.Enum, t, texts(t))
		}
	case stringEnums[t] != nil:
		want("string", "")
		if !sameSet(s.Enum, stringEnums[t]) {
			c.t.Errorf("%s lists %v, and the Go type %s holds %v", where, s.Enum, t, stringEnums[t])
		}
	case k == reflect.String:
		want("string", "")
	case k >= reflect.Int && k <= reflect.Int64:
		want("integer", "")
	case k >= reflect.Uint && k <= reflect.Uint64:
		want("integer", "")
		if s.Minimum == nil || *s.Minimum < 0 {
			c.t.Errorf("%s is the unsigned Go type %s and states no minimum of 0", where, t)
		}
	case k == reflect.Bool:
		want("boolean", "")
	case k == reflect.Slice:
		want("array", "")
		c.compare(where+"[]", s.Items, t.Elem(), request)
	case k == reflect.Map:
		want("object", "")
	case k == reflect.Struct:
		c.object(where, s, t, request)
	default:
		c.t.Errorf("%s: the Go type %s has no rule in this test", where, t)
	}
}

func (c *checker) object(where string, s *schema, t reflect.Type, request bool) {
	c.t.Helper()
	if s.Type != "object" {
		c.t.Errorf("%s is type %q, and the Go type %s is an object", where, s.Type, t)
	}
	fields := map[string]jsonField{}
	for _, f := range jsonFields(t) {
		fields[f.name] = f
		p, ok := s.Properties[f.name]
		if !ok {
			c.t.Errorf("%s does not describe %q, which the Go type %s has", where, f.name, t)
			continue
		}
		c.compare(where+"."+f.name, p, f.typ, request)
	}
	for name := range s.Properties {
		if _, ok := fields[name]; !ok {
			c.t.Errorf("%s describes %q, which the Go type %s does not have", where, name, t)
		}
	}
	for _, name := range s.Required {
		f, ok := fields[name]
		switch {
		case !ok:
			c.t.Errorf("%s requires %q, which it does not describe", where, name)
		case f.omitempty:
			c.t.Errorf("%s requires %q, which encoding/json leaves out when it is empty", where, name)
		}
	}
	if request && (s.AdditionalProperties == nil || *s.AdditionalProperties) {
		c.t.Errorf("%s is read by a decoder that refuses a member it lacks, and does not say additionalProperties: false", where)
	}
}

// jsonSchema is the one JSON schema of a body's content.
func jsonSchema(content map[string]*media) *schema {
	if len(content) != 1 || content["application/json"] == nil {
		return nil
	}
	return content["application/json"].Schema
}

// TestTheBodiesAreTheGoTypes holds every request and answer the document
// describes to the Go type the server reads or writes, member for member
// and type for type, through every schema they reach.
func TestTheBodiesAreTheGoTypes(t *testing.T) {
	d := loadDocument(t)
	c := &checker{t: t, d: d, seen: map[string]bool{}}
	served := map[string]bool{}
	for _, r := range httpapi.Routes() {
		key := r.Method + " " + r.Pattern
		served[key] = true
		b, ok := bodies[key]
		if !ok {
			t.Errorf("%s has no row in bodies, so its bodies are not held to the document", key)
			continue
		}
		op := d.operations()[key]
		if op == nil {
			continue // TestTheDocumentAndTheRoutesAgree names it
		}
		switch rb := op.RequestBody; {
		case b.in == nil && rb != nil:
			t.Errorf("%s describes a request body, and the route reads none", op.OperationID)
		case b.in != nil && (rb == nil || !rb.Required):
			t.Errorf("%s describes no required request body, and the route reads %s", op.OperationID, b.in)
		case b.in != nil:
			c.compare(op.OperationID+" request", jsonSchema(rb.Content), b.in, true)
		}
		status := strconv.Itoa(b.status)
		for code := range op.Responses {
			if strings.HasPrefix(code, "2") && code != status {
				t.Errorf("%s describes the answer %s, and the route answers %s", op.OperationID, code, status)
			}
		}
		r := op.Responses[status]
		switch {
		case r == nil:
			t.Errorf("%s does not describe its answer %s", op.OperationID, status)
		case b.out == nil && len(r.Content) > 0:
			t.Errorf("%s describes a body on %s, and the route answers none", op.OperationID, status)
		case b.out != nil:
			c.compare(op.OperationID+" "+status, jsonSchema(r.Content), b.out, false)
		}
	}
	for key := range bodies {
		if !served[key] {
			t.Errorf("bodies has a row for %s, which the server does not serve", key)
		}
	}
	c.compare("the error envelope", &schema{Ref: "#/components/schemas/Error"}, reflect.TypeFor[httpjson.ErrorEnvelope](), false)
	for name := range d.Components.Schemas {
		if _, ok := schemaTypes[name]; !ok {
			t.Errorf("components.schemas.%s has no Go type in schemaTypes", name)
		} else if !c.seen[name+" true"] && !c.seen[name+" false"] {
			t.Errorf("components.schemas.%s is reached by no body, so it was not held to its Go type", name)
		}
	}
	for name := range schemaTypes {
		if d.Components.Schemas[name] == nil {
			t.Errorf("schemaTypes names %s, which the document does not define", name)
		}
	}
}

// TestTheErrorCodesAreTheServers: the codes the document lists are the
// codes package apierr has, each under the status apierr answers it with
// and with the sentence apierr gives it; every operation lists the
// refusals every route can answer; and every code is documented where it
// can happen.
func TestTheErrorCodesAreTheServers(t *testing.T) {
	d := loadDocument(t)
	all := apierr.Codes()
	code := d.Components.Schemas["ErrorCode"]
	if code == nil || !sameSet(code.Enum, all) {
		t.Fatalf("ErrorCode lists %v, and the server has the codes %v", code, all)
	}
	for _, c := range all {
		if !strings.Contains(code.Description, "`"+c+"` ("+strconv.Itoa(apierr.Status(c))+"), \""+apierr.Message(c)+"\"") {
			t.Errorf("ErrorCode does not describe %s with its status %d and its message %q", c, apierr.Status(c), apierr.Message(c))
		}
	}
	used := map[string]bool{}
	for where, op := range d.operations() {
		listed := map[int][]string{}
		for status, r := range op.Responses {
			n, err := strconv.Atoi(status)
			if err != nil {
				t.Errorf("%s answers %q, which is no status", where, status)
				continue
			}
			if n < 400 {
				continue
			}
			codes, err := d.codes(r)
			if err != nil {
				t.Errorf("%s %d: %v", where, n, err)
				continue
			}
			listed[n] = codes
			for _, c := range codes {
				used[c] = true
				if !slices.Contains(all, c) || apierr.Status(c) != n {
					t.Errorf("%s lists %s under %d, and the server answers it with %d", where, c, n, apierr.Status(c))
				}
				if r.Description == "" && n != http.StatusUnauthorized && n != http.StatusInternalServerError && n != http.StatusServiceUnavailable {
					t.Errorf("%s: the %d answer does not say when it happens", where, n)
				}
			}
		}
		// What every route can answer, and what every route that reads a
		// body can.
		must := map[int][]string{
			http.StatusUnauthorized:        {apierr.CodeMissingToken, apierr.CodeInvalidToken},
			http.StatusForbidden:           {apierr.CodeNotYourDevice},
			http.StatusInternalServerError: {apierr.CodeInternal},
		}
		if op.RequestBody != nil {
			must[http.StatusBadRequest] = []string{apierr.CodeInvalid, apierr.CodeUnknownField}
			must[http.StatusRequestEntityTooLarge] = []string{apierr.CodeTooLarge}
		}
		for n, codes := range must {
			for _, c := range codes {
				if !slices.Contains(listed[n], c) {
					t.Errorf("%s does not list %s under %d, which every such route can answer", where, c, n)
				}
			}
		}
	}
	for _, c := range all {
		if !used[c] {
			t.Errorf("no operation lists %s", c)
		}
	}
}

// TestTheLimitsAreTheServers: a limit the document states, in a schema or
// in words, is the constant the server holds requests to.
func TestTheLimitsAreTheServers(t *testing.T) {
	d := loadDocument(t)
	limit := d.Components.Parameters["Limit"].Schema
	if *limit.Maximum != conv.MaxListLimit || fmt.Sprint(limit.Default) != strconv.Itoa(conv.DefaultListLimit) {
		t.Errorf("limit is at most %d and %v by default, and the server's are %d and %d",
			*limit.Maximum, limit.Default, conv.MaxListLimit, conv.DefaultListLimit)
	}
	if wait := d.Components.Parameters["Wait"].Schema; *wait.Maximum != int64(conv.MaxWait/time.Second) {
		t.Errorf("wait is at most %d seconds, and the server waits at most %s", *wait.Maximum, conv.MaxWait)
	}
	if kps := d.Components.Schemas["KeyPackagePublish"].Properties["key_packages"]; *kps.MaxItems != conv.MaxKeyPackagesPerCall {
		t.Errorf("a publish carries at most %d key packages, and the server takes %d", *kps.MaxItems, conv.MaxKeyPackagesPerCall)
	}
	answer := func(id string, status int) string {
		if op := d.byID(id); op != nil && op.Responses[strconv.Itoa(status)] != nil {
			return op.Responses[strconv.Itoa(status)].Description
		}
		return ""
	}
	member := func(name, property string) string {
		if s := d.Components.Schemas[name]; s != nil && s.Properties[property] != nil {
			return s.Properties[property].Description
		}
		return ""
	}
	for _, c := range []struct {
		where, text string
		limit       int
	}{
		{"Recovery.wrapped", member("Recovery", "wrapped"), conv.MaxSealedBytes},
		{"Transfer.sealed", member("Transfer", "sealed"), conv.MaxSealedBytes},
		{"MessageSend.message", member("MessageSend", "message"), conv.MaxMessageBytes},
		{"ConversationCreate.id", member("ConversationCreate", "id"), messaging.MaxIDBytes},
		{"putRecovery 400", answer("putRecovery", 400), conv.MaxSealedBytes},
		{"leaveTransfer 400", answer("leaveTransfer", 400), conv.MaxSealedBytes},
		{"createConversation 400", answer("createConversation", 400), messaging.MaxIDBytes},
		{"registerDevice 413", answer("registerDevice", 413), messaging.MaxRecords},
		{"putRecovery 413", answer("putRecovery", 413), messaging.MaxRecords},
		{"revokeKey 413", answer("revokeKey", 413), messaging.MaxRevocations},
		{"publishKeyPackages 413", answer("publishKeyPackages", 413), conv.MaxKeyPackagesPerCall},
		{"publishKeyPackages 413", answer("publishKeyPackages", 413), conv.MaxKeyPackagesPerDevice},
		{"sendMessage 413", answer("sendMessage", 413), conv.MaxMessageBytes},
		{"listConversations 400", answer("listConversations", 400), conv.MaxListLimit},
	} {
		if !strings.Contains(c.text, strconv.Itoa(c.limit)) {
			t.Errorf("%s does not state the server's limit %d: %q", c.where, c.limit, c.text)
		}
	}
}

// holdToDocument checks one answer of the server against the operation
// the document describes for its request: its status is one the operation
// lists, and its body is that status's schema, member for member, so a
// refusal's code is one listed under its status. Every request the tests
// of this package send goes through it.
func holdToDocument(t testing.TB, method, path string, status int, body []byte) {
	t.Helper()
	d := loadDocument(t)
	route, _, _ := strings.Cut(httpapi.Prefix+path, "?")
	pattern, op := d.match(method, route)
	if op == nil {
		t.Errorf("%s %s: api/openapi.yaml describes no operation for it", method, route)
		return
	}
	where := fmt.Sprintf("%s answered %d", op.OperationID, status)
	r := op.Responses[strconv.Itoa(status)]
	if r == nil {
		t.Errorf("%s %s answered %d, which %s does not list", method, pattern, status, op.OperationID)
		return
	}
	r = d.response(r)
	if r == nil {
		t.Errorf("%s: the answer refers to no component", where)
		return
	}
	if len(r.Content) == 0 {
		if len(body) > 0 {
			t.Errorf("%s with a body, and the document describes none: %s", where, body)
		}
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Errorf("%s with a body that is not JSON: %v", where, err)
		return
	}
	d.validate(t, where, v, jsonSchema(r.Content))
	if status >= 400 {
		var env httpjson.ErrorEnvelope
		if err := json.Unmarshal(body, &env); err != nil || env.Error.Message != apierr.Message(env.Error.Code) {
			t.Errorf("%s with the message %q for %s: %v", where, env.Error.Message, env.Error.Code, err)
		}
	}
}

// match is the operation a request reaches: the path template it fits
// with the most literal segments, as the server's mux picks one.
func (d *document) match(method, route string) (string, *operation) {
	segments := strings.Split(route, "/")
	best, literals := "", -1
	var found *operation
	for pattern, item := range d.Paths {
		op := item[strings.ToLower(method)]
		parts := strings.Split(pattern, "/")
		if op == nil || len(parts) != len(segments) {
			continue
		}
		n, fits := 0, true
		for i, part := range parts {
			if placeholder.MatchString(part) {
				fits = fits && segments[i] != ""
				continue
			}
			fits = fits && part == segments[i]
			n++
		}
		if fits && n > literals {
			best, literals, found = pattern, n, op
		}
	}
	return best, found
}

// validate checks a decoded JSON value against a schema, in the part of
// JSON Schema the document uses.
func (d *document) validate(t testing.TB, where string, v any, s *schema) {
	t.Helper()
	if s == nil {
		t.Errorf("%s: no schema describes it", where)
		return
	}
	if s.Ref != "" {
		_, target := d.schemaAt(s.Ref)
		if target == nil {
			t.Errorf("%s refers to %s, which is not defined", where, s.Ref)
			return
		}
		d.validate(t, where, v, target)
		return
	}
	for _, part := range s.AllOf {
		d.validate(t, where, v, part)
	}
	if len(s.Enum) > 0 {
		if str, ok := v.(string); !ok || !slices.Contains(s.Enum, str) {
			t.Errorf("%s is %v, which is not one of %v", where, v, s.Enum)
		}
	}
	switch s.Type {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			t.Errorf("%s is %T, not an object", where, v)
			return
		}
		for name := range m {
			if s.Properties[name] == nil {
				t.Errorf("%s has %q, which the document does not describe", where, name)
			}
		}
		for _, name := range s.Required {
			if _, ok := m[name]; !ok {
				t.Errorf("%s lacks %q, which the document requires", where, name)
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			t.Errorf("%s is %T, not an array", where, v)
			return
		}
		for i, e := range a {
			d.validate(t, fmt.Sprintf("%s[%d]", where, i), e, s.Items)
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			t.Errorf("%s is %T, not a string", where, v)
			return
		}
		if _, err := base64.StdEncoding.DecodeString(str); s.ContentEncoding == "base64" && err != nil {
			t.Errorf("%s is not standard base64: %v", where, err)
		}
		if s.Format == "date-time" {
			if at, err := time.Parse(time.RFC3339Nano, str); err != nil || at.IsZero() {
				t.Errorf("%s is %q, which is not a time the server set", where, str)
			}
		}
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			t.Errorf("%s is %T, not an integer", where, v)
			return
		}
		i, err := strconv.ParseInt(n.String(), 10, 64)
		switch {
		case err != nil:
			t.Errorf("%s is %s, not an integer: %v", where, n, err)
		case s.Minimum != nil && i < *s.Minimum, s.Maximum != nil && i > *s.Maximum:
			t.Errorf("%s is %d, outside its range", where, i)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			t.Errorf("%s is %T, not a boolean", where, v)
		}
	case "":
	default:
		t.Errorf("%s: this test does not know the type %q", where, s.Type)
	}
	if m, ok := v.(map[string]any); ok {
		for name, p := range s.Properties {
			if e, ok := m[name]; ok {
				d.validate(t, where+"."+name, e, p)
			}
		}
	}
}
