# SPDX-FileCopyrightText: 2026 Latere AI
# SPDX-License-Identifier: Apache-2.0

# The server image: sermod and nothing else. Build it from the repository
# root:
#
#   podman build -t sermod .
#
# and stamp the release it is built as:
#
#   podman build -t sermod --build-arg VERSION="$(git describe --tags --always)" .
#
# The release pipeline builds this same file for linux/amd64 and
# linux/arm64, so a released image differs from a developer's in its
# version and in nothing else.

# The build stage runs on the machine that builds, whatever platform the
# image is for, and cross-compiles: the binary has no cgo, so the compiler
# needs no emulation. TARGETOS and TARGETARCH are set by the builder per
# platform; a builder that sets neither leaves them empty, and the compiler
# then targets the platform it runs on.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
# Empty leaves the version to what the Go build records.
ARG VERSION=
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
      -ldflags "-X latere.ai/x/sermo/internal/version.Version=${VERSION}" \
      -o /out/sermod ./cmd/sermod

# sermod starts no other program and writes no file: every fact it keeps is
# in the database. So the runtime stage is distroless: the roots it
# verifies certificates against, no shell, no package manager. The user is
# numeric, so a cluster that requires a non-root user can check it without
# reading the image's passwd file. sermod takes no arguments; it reads its
# settings from SERMO_* variables.
FROM gcr.io/distroless/static-debian12:nonroot
EXPOSE 8080
USER 65532:65532
COPY --from=build /out/sermod /usr/local/bin/sermod
ENTRYPOINT ["/usr/local/bin/sermod"]
