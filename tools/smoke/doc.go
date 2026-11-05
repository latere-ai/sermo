// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package smoke holds the test for release.sh, the live check the release
// pipeline runs against the public origin after a rollout.
//
// The script is shell so that an operator can read it and run it without a
// Go toolchain; this package keeps it honest against a stub server.
package smoke
