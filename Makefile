# SPDX-FileCopyrightText: 2026 Latere AI
# SPDX-License-Identifier: Apache-2.0

GO ?= go

.PHONY: check hooks specs

# The whole bar. Every gate lives in latere.ai/x/ci-gate, pinned as a tool
# in go.mod and configured in .lateregate.yaml, so this target is a name for
# `go tool lateregate` and nothing else. One gate at a time: `go tool
# lateregate cover`. The plan: `go tool lateregate list`.
check:
	@$(GO) tool lateregate

.DEFAULT_GOAL := check

# specs checks the spec tree alone.
specs:
	@$(GO) tool lateregate spec-lint

# hooks points git at the repository hook directory.
hooks:
	git config core.hooksPath .githooks
	@echo "installed git hooks (core.hooksPath=.githooks)"
