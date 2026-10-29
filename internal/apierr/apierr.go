// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package apierr is the error table of specs/002-api.md. An error has
// one code, one fixed sentence a person reads in message, and the
// developer detail of its instance apart.
package apierr

import (
	"errors"
	"net/http"

	"latere.ai/x/pkg/httpjson"
)

// The error codes.
const (
	CodeInvalid               = "invalid"
	CodeUnknownField          = "unknown_field"
	CodeMissingToken          = "missing_token"
	CodeInvalidToken          = "invalid_token"
	CodeNotYourDevice         = "not_your_device"
	CodeForbidden             = "forbidden"
	CodeNotFound              = "not_found"
	CodeExists                = "exists"
	CodeEpochTaken            = "epoch_taken"
	CodeWrongEpoch            = "wrong_epoch"
	CodeRefused               = "refused"
	CodeTooLarge              = "too_large"
	CodeAuthorizerUnavailable = "authorizer_unavailable"
	CodeInternal              = "internal"
)

type kind struct {
	status  int
	message string
}

var table = map[string]kind{
	CodeInvalid:               {http.StatusBadRequest, "The request could not be read."},
	CodeUnknownField:          {http.StatusBadRequest, "The request has a member this API does not take."},
	CodeMissingToken:          {http.StatusUnauthorized, "This request needs a token."},
	CodeInvalidToken:          {http.StatusUnauthorized, "The token was refused. Sign in again."},
	CodeNotYourDevice:         {http.StatusForbidden, "This device is not one of yours. Set it up again."},
	CodeForbidden:             {http.StatusForbidden, "You can't do that here."},
	CodeNotFound:              {http.StatusNotFound, "That isn't here."},
	CodeExists:                {http.StatusConflict, "That exists already."},
	CodeEpochTaken:            {http.StatusConflict, "Someone else changed the conversation first. Try again."},
	CodeWrongEpoch:            {http.StatusConflict, "The conversation has moved on. Catch up and send again."},
	CodeRefused:               {http.StatusUnprocessableEntity, "The conversation's rules don't allow that change."},
	CodeTooLarge:              {http.StatusRequestEntityTooLarge, "That is too large to send."},
	CodeAuthorizerUnavailable: {http.StatusServiceUnavailable, "This can't be checked right now. Try again shortly."},
	CodeInternal:              {http.StatusInternalServerError, "Something went wrong on our side."},
}

// Codes lists every code.
func Codes() []string {
	out := make([]string, 0, len(table))
	for c := range table {
		out = append(out, c)
	}
	return out
}

// Status is a code's status, 500 for a code the table lacks.
func Status(code string) int {
	if k, ok := table[code]; ok {
		return k.status
	}
	return http.StatusInternalServerError
}

// Message is a code's fixed sentence.
func Message(code string) string { return table[code].message }

// Error is one error answered: its code and the developer detail.
type Error struct {
	Code   string
	Detail string
	cause  error
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// Unwrap is the error the answer was made from, for the log.
func (e *Error) Unwrap() error { return e.cause }

// New is an error with a code and a detail.
func New(code, detail string) *Error { return &Error{Code: code, Detail: detail} }

// Wrap is an error with a code whose detail is cause's text.
func Wrap(code string, cause error) *Error {
	return &Error{Code: code, Detail: cause.Error(), cause: cause}
}

// Internal is an error nobody classified: its cause goes to the log and
// never to the caller.
func Internal(cause error) *Error { return &Error{Code: CodeInternal, cause: cause} }

// Classify is the answer an error makes: itself when it is an *Error,
// and internal otherwise.
func Classify(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}

// Write answers an error and returns it classified, for the log.
func Write(w http.ResponseWriter, err error) *Error {
	e := Classify(err)
	body := httpjson.Error{Code: e.Code, Message: Message(e.Code)}
	if e.Detail != "" {
		body.Details = map[string]any{"detail": e.Detail}
	}
	httpjson.WriteError(w, Status(e.Code), body)
	return e
}
