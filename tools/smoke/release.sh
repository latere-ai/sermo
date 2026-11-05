#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Latere AI
# SPDX-License-Identifier: Apache-2.0
#
# The live check after a deploy of sermod. The release pipeline runs it once
# the rollout is done; an operator can run it by hand against an installation.
# It sends unauthenticated, read-only requests and changes nothing, so it can
# run any number of times. It does not wait: the caller runs it again until it
# passes.
#
# Required tools: curl, grep.
#
# Environment:
#   BASE_URL   the public origin that serves the API, such as
#              https://api.latere.ai; required
#   TAG        the release being proved. Sermo's version is not served on any
#              public route (see below), so it is recorded in the evidence and
#              not compared with anything.
#   COMMIT     the release commit, for the evidence
#   DEPLOY_URL the run that deployed it, for the evidence
#   OUTPUT_MD  where to write the Markdown evidence; nowhere when unset
#
# What is public: the ingress claims /v1/messaging on api.latere.ai and
# nothing else. sermod serves /livez, /readyz and /version at its own root,
# which no ingress rule routes, so there is no public health route and no
# public route that reports the version. Missing: a version (and a readiness)
# route under /v1/messaging. Until one exists, the one thing this can prove is
# that the origin routes the prefix to sermod, which answers an unauthenticated
# request with 401 and a JSON error. A 404 means the route is not claimed.

set -euo pipefail

BASE_URL="${BASE_URL:-}"
BASE_URL="${BASE_URL%/}"
TAG="${TAG:-}"
COMMIT="${COMMIT:-unknown}"
DEPLOY_URL="${DEPLOY_URL:-}"
OUTPUT_MD="${OUTPUT_MD:-}"

pass() { printf 'ok: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ -n "$BASE_URL" ] || fail "BASE_URL is required; this smoke has no default target"
for cmd in curl grep; do
  command -v "$cmd" >/dev/null || fail "$cmd is required"
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

path="/v1/messaging/conversations"
code=$(curl -sS --max-time 20 -o "$tmp/body" -w '%{http_code}' "${BASE_URL}${path}") \
  || fail "GET ${path}: no answer from ${BASE_URL}"
[ "$code" = "401" ] || fail "GET ${path}: expected 401, got ${code} (body: $(head -c 200 "$tmp/body" 2>/dev/null || true))"
grep -q '"error"' "$tmp/body" || fail "GET ${path}: 401 without a JSON error, so sermod did not answer"
pass "GET ${path} (401, answered by sermod)"

if [ -n "$TAG" ]; then
  pass "version not publicly readable; ${TAG} not compared"
fi

if [ -n "$OUTPUT_MD" ]; then
  {
    echo "<!-- release-evidence -->"
    echo
    echo "## Release evidence"
    echo
    echo "- Tag: \`${TAG:-unknown}\`"
    echo "- Commit: \`${COMMIT}\`"
    [ -n "$DEPLOY_URL" ] && echo "- Deploy: ${DEPLOY_URL}"
    echo "- Origin: ${BASE_URL}"
    echo "- Route: \`GET ${path}\` answered 401 with a JSON error, so the origin routes the prefix to sermod"
    echo "- Version: not publicly readable, so the served version was not compared with the tag"
  } > "$OUTPUT_MD"
fi

printf '\nrelease smoke passed\n'
