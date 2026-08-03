# Copyright IBM Corp. 2026
# SPDX-License-Identifier: MPL-2.0

# certbuild captures ca-certificates for HTTPS fetches.
FROM docker.mirror.hashicorp.services/alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1 AS certbuild
RUN apk add --no-cache ca-certificates

# build compiles the helper.
FROM golang:1.25.5-alpine@sha256:ac09a5f469f307e5da71e766b0bd59c9c49ea460a528cc3e6686513d64a6f1fb AS build
WORKDIR /build
COPY go.mod go.sum ./
COPY scripts/fetch-certs ./scripts/fetch-certs
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -o /out/certs-puller ./scripts/fetch-certs

# Run as a tiny scratch image.
FROM scratch
WORKDIR /app
COPY --from=build /out/certs-puller /app/certs-puller
COPY --from=certbuild /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/app/certs-puller"]
