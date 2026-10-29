// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package authorizer is the vocabulary an authorization endpoint for
// Sermo is written against: the actions sermod asks, the resource kind
// each acts on, and the fields a resource carries. Import it to write the
// endpoint sermod asks, in Go, without keeping a copy of the strings.
//
// The envelope on the wire is latere.ai/x/pkg/authz's: sermod posts a
// request with the caller's subject, its claims, an action and a
// resource, and reads back an allow or a deny. Vocabulary is the whole
// action table as an authz.Vocabulary, which the conformance suite of
// latere.ai/x/pkg/authz/conformance drives its cases from.
//
// The resource carries its fields flat beside its kind and id, under the
// names of the Field constants; Fields lists the fields each action may
// send. A field sermod does not know for a request is absent, never
// empty. Lists of people are lists of subjects.
//
// Sermo decides what the conversation's rules decide, which every device
// decides too, before it asks: a commit that breaks them is refused and
// never reaches the authorizer. What the authorizer decides is the rest:
// who may talk to whom, limits, blocks, an account's standing.
//
// The promise: additive within a module major. An action string never
// changes and never disappears, and a field is only ever added.
package authorizer
