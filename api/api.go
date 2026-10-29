// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package api carries the OpenAPI 3.1 description of sermod's HTTP API,
// openapi.yaml, the document a client is written or generated from.
package api

import _ "embed"

// Document is openapi.yaml as this build carries it. The tests of
// internal/httpapi hold it to the routes the server registers, to the Go
// types of their bodies and to the error codes the server answers.
//
//go:embed openapi.yaml
var Document []byte
