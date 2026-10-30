// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package version holds the release a binary was built as, which the
// linker stamps.
package version

// Version is set at link time by the image's build stage, to the release
// tag. A binary built any other way leaves it empty, and the server then
// reports what the Go build recorded: the module version of a `go
// install`, or the commit of a checkout.
var Version = ""
