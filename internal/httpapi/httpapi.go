// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package httpapi is the HTTP API of specs/002-api.md over package conv:
// the routes under /v1/messaging, their JSON, the token every route
// needs and the device a request speaks for. A body is decoded strictly,
// an error is answered in the envelope of package apierr, and nothing a
// request carries is logged but its route, its code and its detail.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"latere.ai/x/sdk-go/messaging"

	"latere.ai/x/sermo/internal/access"
	"latere.ai/x/sermo/internal/apierr"
	"latere.ai/x/sermo/internal/conv"
	"latere.ai/x/sermo/internal/store"
)

// Prefix is where the API is served.
const Prefix = "/v1/messaging"

// DeviceHeader names the device a request speaks for.
const DeviceHeader = "Sermo-Device"

// Options build the handler.
type Options struct {
	Service       *conv.Service
	Authenticator access.Authenticator
	// MaxRequestBytes bounds a request body.
	MaxRequestBytes int64
	Logger          *slog.Logger
}

// API is the handler.
type API struct {
	svc  *conv.Service
	auth access.Authenticator
	max  int64
	log  *slog.Logger
	mux  *http.ServeMux
}

// New builds the handler.
func New(o Options) (*API, error) {
	if o.Service == nil || o.Authenticator == nil || o.MaxRequestBytes <= 0 {
		return nil, errors.New("httpapi: a service, an authenticator and a request bound are needed")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	a := &API{svc: o.Service, auth: o.Authenticator, max: o.MaxRequestBytes, log: log, mux: http.NewServeMux()}
	for _, r := range a.routes() {
		a.mux.Handle(r.method+" "+Prefix+r.path, a.wrap(r))
	}
	return a, nil
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// need is what a route needs of its request beyond a token.
type need uint8

const (
	anyCaller need = iota
	// asDevice routes speak for a device of the caller's that stands.
	asDevice
)

type route struct {
	method, path string
	need         need
	handle       func(ctx context.Context, w conv.Who, r *http.Request) (int, any, error)
}

func (a *API) routes() []route {
	return []route{
		{"GET", "/service", anyCaller, a.service},
		{"GET", "/people/{person}/devices", anyCaller, a.devices},
		{"PUT", "/devices/{device}", anyCaller, a.registerDevice},
		{"POST", "/revocations", anyCaller, a.revoke},
		{"PUT", "/recovery", anyCaller, a.putRecovery},
		{"GET", "/recovery", anyCaller, a.getRecovery},
		{"POST", "/devices/{device}/transfer", anyCaller, a.putTransfer},
		{"GET", "/devices/{device}/transfer", asDevice, a.takeTransfer},
		{"POST", "/key-packages", asDevice, a.publishKeyPackages},
		{"GET", "/key-packages", asDevice, a.keyPackageCount},
		{"POST", "/key-packages/claim", anyCaller, a.claimKeyPackages},
		{"POST", "/conversations", asDevice, a.create},
		{"GET", "/conversations", anyCaller, a.list},
		{"GET", "/conversations/{id}", anyCaller, a.get},
		{"GET", "/conversations/{id}/group-info", asDevice, a.groupInfo},
		{"POST", "/conversations/{id}/messages", asDevice, a.send},
		{"GET", "/conversations/{id}/messages", asDevice, a.messages},
		{"POST", "/conversations/{id}/backup", asDevice, a.putBackup},
		{"GET", "/conversations/{id}/backup", asDevice, a.backup},
		{"GET", "/welcomes", asDevice, a.welcomes},
		{"DELETE", "/welcomes/{id}", asDevice, a.deleteWelcome},
		{"GET", "/conversations/{id}/people/{person}", anyCaller, a.membership},
	}
}

// wrap authenticates a request, checks its device, runs the route and
// answers it.
func (a *API) wrap(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, a.max)
		status, body, err := a.serve(rt, r)
		if err != nil {
			e := apierr.Write(w, err)
			level := slog.LevelInfo
			if e.Code == apierr.CodeInternal || e.Code == apierr.CodeAuthorizerUnavailable {
				level = slog.LevelError
			}
			a.log.LogAttrs(r.Context(), level, "request refused",
				slog.String("route", rt.method+" "+rt.path), slog.String("code", e.Code),
				slog.String("detail", e.Detail), slog.Any("cause", errors.Unwrap(e)))
			return
		}
		if body == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, a.log, status, body)
	})
}

func (a *API) serve(rt route, r *http.Request) (int, any, error) {
	caller, err := a.auth.Authenticate(r)
	if err != nil {
		var te *access.TokenError
		switch {
		case errors.Is(err, access.ErrMissingToken):
			return 0, nil, apierr.New(apierr.CodeMissingToken, "")
		case errors.As(err, &te):
			return 0, nil, apierr.New(apierr.CodeInvalidToken, te.Reason)
		}
		return 0, nil, err
	}
	who := conv.Who{Caller: caller, Person: caller.Sub, Device: r.Header.Get(DeviceHeader), Request: r}
	if who.Device != "" || rt.need == asDevice {
		if who.Device == "" {
			return 0, nil, apierr.New(apierr.CodeNotYourDevice, "the route speaks for a device: send "+DeviceHeader)
		}
		if err := a.svc.CheckDevice(r.Context(), who.Person, who.Device); err != nil {
			return 0, nil, err
		}
	}
	return rt.handle(r.Context(), who, r)
}

func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		e := apierr.Write(w, apierr.Internal(err))
		log.Error("encoding a response", slog.String("code", e.Code), slog.Any("cause", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(append(body, '\n')); err != nil {
		log.Info("writing a response", slog.Any("cause", err))
	}
}

// decode reads a body strictly: one JSON value with no member the type
// lacks.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if dec.More() || dec.Decode(&struct{}{}) != io.EOF {
			return apierr.New(apierr.CodeInvalid, "the body holds more than one JSON value")
		}
		return nil
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return apierr.New(apierr.CodeTooLarge, "the body is over the server's bound")
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return apierr.New(apierr.CodeUnknownField, strings.TrimPrefix(err.Error(), "json: "))
	case errors.Is(err, io.EOF):
		return apierr.New(apierr.CodeInvalid, "the body is empty")
	}
	return apierr.Wrap(apierr.CodeInvalid, err)
}

func query(r *http.Request, name string, def, max int64) (int64, error) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > max {
		return 0, apierr.New(apierr.CodeInvalid, name+" is a number from 0 to "+strconv.FormatInt(max, 10))
	}
	return n, nil
}

// The bodies.

// Service is what a device needs of this server to create a group: the
// external sender every conversation's group names.
type Service struct {
	ExternalSender ExternalSender `json:"external_sender"`
}

// ExternalSender is Sermo's key and the identity of its basic
// credential.
type ExternalSender struct {
	SignatureKey []byte `json:"signature_key"`
	Identity     string `json:"identity"`
}

// DeviceList is a person's directory as Sermo holds it.
type DeviceList struct {
	Records     []messaging.DeviceRecord `json:"records"`
	Revocations []messaging.Revocation   `json:"revocations"`
}

// RecoveryBody is a recovery record with the wrapped backup key.
type RecoveryBody struct {
	Record  messaging.DeviceRecord `json:"record"`
	Wrapped []byte                 `json:"wrapped"`
}

// TransferBody is the backup key sealed to a device.
type TransferBody struct {
	Sealed []byte `json:"sealed"`
}

// KeyPackagesBody is what a device publishes.
type KeyPackagesBody struct {
	KeyPackages [][]byte `json:"key_packages"`
	LastResort  []byte   `json:"last_resort,omitempty"`
}

// KeyPackageCount is how many a device has left.
type KeyPackageCount struct {
	Count      int  `json:"count"`
	LastResort bool `json:"last_resort"`
}

// ClaimBody asks for a key package of each device of a person.
type ClaimBody struct {
	Person       string `json:"person"`
	Conversation string `json:"conversation"`
}

// ClaimedKeyPackage is one device's key package.
type ClaimedKeyPackage struct {
	Device     string `json:"device"`
	KeyPackage []byte `json:"key_package"`
}

// ClaimedList is what a claim handed out.
type ClaimedList struct {
	KeyPackages []ClaimedKeyPackage `json:"key_packages"`
}

// CreateBody creates a conversation.
type CreateBody struct {
	ID        string `json:"id"`
	GroupInfo []byte `json:"group_info"`
}

// Conversation is one conversation as the API shows it.
type Conversation struct {
	ID      string          `json:"id"`
	Kind    messaging.Kind  `json:"kind"`
	Level   messaging.Level `json:"level"`
	People  []string        `json:"people"`
	Owners  []string        `json:"owners"`
	Epoch   uint64          `json:"epoch"`
	Seq     int64           `json:"seq"`
	Created time.Time       `json:"created"`
	Updated time.Time       `json:"updated"`
}

func conversationOf(c *store.Conversation) Conversation {
	return Conversation{ID: c.ID, Kind: c.Kind, Level: c.Level, People: nonNil(c.People), Owners: nonNil(c.Owners),
		Epoch: c.Epoch, Seq: c.Seq, Created: c.Created, Updated: c.Updated}
}

// ConversationList is a page of conversations.
type ConversationList struct {
	Conversations []Conversation `json:"conversations"`
	// Next is the cursor of the next page, empty on the last.
	Next string `json:"next,omitempty"`
}

// GroupInfoBody is a conversation's latest group info.
type GroupInfoBody struct {
	GroupInfo []byte `json:"group_info"`
}

// SendBody is one MLS message.
type SendBody struct {
	Message   []byte `json:"message"`
	Welcome   []byte `json:"welcome,omitempty"`
	GroupInfo []byte `json:"group_info,omitempty"`
}

// Sent is what a send appended.
type Sent struct {
	Seq   int64             `json:"seq"`
	Epoch uint64            `json:"epoch"`
	Kind  store.MessageKind `json:"kind"`
}

// Message is one message of the log.
type Message struct {
	Seq     int64             `json:"seq"`
	Epoch   uint64            `json:"epoch"`
	Kind    store.MessageKind `json:"kind"`
	Message []byte            `json:"message"`
	// Person and Device sent it; both are empty for Sermo's own
	// proposal.
	Person  string    `json:"person,omitempty"`
	Device  string    `json:"device,omitempty"`
	Created time.Time `json:"created"`
}

// MessageList is a page of the log.
type MessageList struct {
	Messages []Message `json:"messages"`
	// Next is the sequence number to read after next.
	Next int64 `json:"next"`
}

// BackupRecord is one sealed record of the caller's history: the id the
// caller's devices derived for it and the record under their backup key.
type BackupRecord struct {
	ID     string `json:"id"`
	Sealed []byte `json:"sealed"`
}

// BackupPut is the records a device stores.
type BackupPut struct {
	Records []BackupRecord `json:"records"`
}

// BackupStored says how many of the records were new.
type BackupStored struct {
	Added int `json:"added"`
}

// StoredBackupRecord is a record as it is listed, with the cursor the
// server gave it.
type StoredBackupRecord struct {
	ID      string    `json:"id"`
	Sealed  []byte    `json:"sealed"`
	Cursor  int64     `json:"cursor"`
	Created time.Time `json:"created"`
}

// BackupList is a page of the caller's records of a conversation.
type BackupList struct {
	Records []StoredBackupRecord `json:"records"`
	// Next is the cursor of the next page; it is set only when this one is
	// full, and the next may be empty.
	Next int64 `json:"next,omitempty"`
}

// Welcome is one Welcome for the calling device.
type Welcome struct {
	ID           string    `json:"id"`
	Conversation string    `json:"conversation"`
	Seq          int64     `json:"seq"`
	Welcome      []byte    `json:"welcome"`
	Notice       []byte    `json:"notice,omitempty"`
	Created      time.Time `json:"created"`
}

// WelcomeList is every Welcome for the calling device.
type WelcomeList struct {
	Welcomes []Welcome `json:"welcomes"`
}

// Membership answers whether a person is one of a conversation's people.
type Membership struct {
	Person string `json:"person"`
	Member bool   `json:"member"`
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// The routes.

func (a *API) service(context.Context, conv.Who, *http.Request) (int, any, error) {
	es := a.svc.ExternalSender()
	return http.StatusOK, Service{ExternalSender: ExternalSender{SignatureKey: es.SignatureKey, Identity: string(es.Credential.Identity)}}, nil
}

func (a *API) devices(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	d, err := a.svc.Devices(ctx, w, r.PathValue("person"))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, DeviceList{Records: nonNil(d.Records), Revocations: nonNil(d.Revocations)}, nil
}

func (a *API) registerDevice(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var rec messaging.DeviceRecord
	if err := decode(r, &rec); err != nil {
		return 0, nil, err
	}
	if rec.ID != r.PathValue("device") {
		return 0, nil, apierr.New(apierr.CodeInvalid, "the record's id is the path's device")
	}
	return http.StatusNoContent, nil, a.svc.RegisterDevice(ctx, w, rec)
}

func (a *API) revoke(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var v messaging.Revocation
	if err := decode(r, &v); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, a.svc.Revoke(ctx, w, v)
}

func (a *API) putRecovery(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b RecoveryBody
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, a.svc.PutRecovery(ctx, w, b.Record, b.Wrapped)
}

func (a *API) getRecovery(ctx context.Context, w conv.Who, _ *http.Request) (int, any, error) {
	rec, err := a.svc.GetRecovery(ctx, w)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, RecoveryBody{Record: rec.Record, Wrapped: rec.Wrapped}, nil
}

func (a *API) putTransfer(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b TransferBody
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, a.svc.PutTransfer(ctx, w, r.PathValue("device"), b.Sealed)
}

func (a *API) takeTransfer(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	sealed, err := a.svc.TakeTransfer(ctx, w, r.PathValue("device"))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, TransferBody{Sealed: sealed}, nil
}

func (a *API) publishKeyPackages(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b KeyPackagesBody
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, a.svc.PublishKeyPackages(ctx, w, b.KeyPackages, b.LastResort)
}

func (a *API) keyPackageCount(ctx context.Context, w conv.Who, _ *http.Request) (int, any, error) {
	n, last, err := a.svc.KeyPackageCount(ctx, w)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, KeyPackageCount{Count: n, LastResort: last}, nil
}

func (a *API) claimKeyPackages(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b ClaimBody
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	claimed, err := a.svc.ClaimKeyPackages(ctx, w, b.Person, b.Conversation)
	if err != nil {
		return 0, nil, err
	}
	out := ClaimedList{KeyPackages: []ClaimedKeyPackage{}}
	for _, c := range claimed {
		out.KeyPackages = append(out.KeyPackages, ClaimedKeyPackage{Device: c.Device, KeyPackage: c.KeyPackage})
	}
	return http.StatusOK, out, nil
}

func (a *API) create(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b CreateBody
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	c, err := a.svc.Create(ctx, w, b.ID, b.GroupInfo)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, conversationOf(c), nil
}

func (a *API) list(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	limit, err := query(r, "limit", conv.DefaultListLimit, conv.MaxListLimit)
	if err != nil {
		return 0, nil, err
	}
	if limit == 0 {
		// A limit of 0 is the default page, which the next cursor below
		// must know to name the page after a full one.
		limit = conv.DefaultListLimit
	}
	cs, err := a.svc.List(ctx, w, r.URL.Query().Get("after"), int(limit))
	if err != nil {
		return 0, nil, err
	}
	out := ConversationList{Conversations: []Conversation{}}
	for i := range cs {
		out.Conversations = append(out.Conversations, conversationOf(&cs[i]))
	}
	if int64(len(cs)) == limit {
		out.Next = cs[len(cs)-1].ID
	}
	return http.StatusOK, out, nil
}

func (a *API) get(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	c, err := a.svc.Get(ctx, w, r.PathValue("id"))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, conversationOf(c), nil
}

func (a *API) groupInfo(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	gi, err := a.svc.GroupInfo(ctx, w, r.PathValue("id"))
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, GroupInfoBody{GroupInfo: gi}, nil
}

func (a *API) send(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b SendBody
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	sent, err := a.svc.Send(ctx, w, r.PathValue("id"), conv.Send{Message: b.Message, Welcome: b.Welcome, GroupInfo: b.GroupInfo})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, Sent{Seq: sent.Seq, Epoch: sent.Epoch, Kind: sent.Kind}, nil
}

func (a *API) messages(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	after, err := query(r, "after", 0, 1<<62)
	if err != nil {
		return 0, nil, err
	}
	limit, err := query(r, "limit", conv.DefaultListLimit, conv.MaxListLimit)
	if err != nil {
		return 0, nil, err
	}
	wait, err := query(r, "wait", 0, int64(conv.MaxWait/time.Second))
	if err != nil {
		return 0, nil, err
	}
	page, err := a.svc.Messages(ctx, w, r.PathValue("id"), after, int(limit), time.Duration(wait)*time.Second)
	if err != nil {
		return 0, nil, err
	}
	out := MessageList{Messages: []Message{}, Next: page.Next}
	for _, m := range page.Messages {
		out.Messages = append(out.Messages, Message{Seq: m.Seq, Epoch: m.Epoch, Kind: m.Kind, Message: m.Data,
			Person: m.Person, Device: m.Device, Created: m.Created})
	}
	return http.StatusOK, out, nil
}

func (a *API) welcomes(ctx context.Context, w conv.Who, _ *http.Request) (int, any, error) {
	ws, err := a.svc.Welcomes(ctx, w)
	if err != nil {
		return 0, nil, err
	}
	out := WelcomeList{Welcomes: []Welcome{}}
	for _, wl := range ws {
		out.Welcomes = append(out.Welcomes, Welcome{ID: wl.ID, Conversation: wl.Conversation, Seq: wl.Seq,
			Welcome: wl.Data, Notice: wl.Notice, Created: wl.Created})
	}
	return http.StatusOK, out, nil
}

func (a *API) deleteWelcome(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	return http.StatusNoContent, nil, a.svc.DeleteWelcome(ctx, w, r.PathValue("id"))
}

func (a *API) membership(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	person := r.PathValue("person")
	member, err := a.svc.Membership(ctx, w, r.PathValue("id"), person)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, Membership{Person: person, Member: member}, nil
}

func (a *API) putBackup(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	var b BackupPut
	if err := decode(r, &b); err != nil {
		return 0, nil, err
	}
	in := make([]conv.BackupRecord, 0, len(b.Records))
	for _, x := range b.Records {
		in = append(in, conv.BackupRecord{ID: x.ID, Sealed: x.Sealed})
	}
	n, err := a.svc.PutBackup(ctx, w, r.PathValue("id"), in)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, BackupStored{Added: n}, nil
}

func (a *API) backup(ctx context.Context, w conv.Who, r *http.Request) (int, any, error) {
	cursor, err := query(r, "cursor", 0, 1<<62)
	if err != nil {
		return 0, nil, err
	}
	limit, err := query(r, "limit", conv.DefaultListLimit, conv.MaxListLimit)
	if err != nil {
		return 0, nil, err
	}
	if limit == 0 {
		limit = conv.DefaultListLimit
	}
	var newest bool
	switch r.URL.Query().Get("order") {
	case "", "oldest":
	case "newest":
		newest = true
	default:
		return 0, nil, apierr.New(apierr.CodeInvalid, "order is oldest or newest")
	}
	recs, err := a.svc.Backup(ctx, w, r.PathValue("id"), cursor, newest, int(limit))
	if err != nil {
		return 0, nil, err
	}
	out := BackupList{Records: []StoredBackupRecord{}}
	for _, x := range recs {
		out.Records = append(out.Records, StoredBackupRecord{ID: x.ID, Sealed: x.Sealed, Cursor: x.Seq, Created: x.Created})
	}
	if int64(len(recs)) == limit {
		out.Next = recs[len(recs)-1].Seq
	}
	return http.StatusOK, out, nil
}
