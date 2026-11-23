# syntax=docker/dockerfile:1

# Build stage: Chainguard Go builder with verified digest
# Verification: docker pull cgr.dev/chainguard/go:latest-dev
# Command output: Digest: sha256:f90bc942e1f05e2d6b3b37af550fe50bbac9134a267b529573eddb50996656ab
FROM cgr.dev/chainguard/go@sha256:f90bc942e1f05e2d6b3b37af550fe50bbac9134a267b529573eddb50996656ab AS builder

WORKDIR /work
COPY go.mod go.sum* ./
ARG OFFLINE_GO_BUILD=0
RUN if [ "$OFFLINE_GO_BUILD" = 0 ]; then go mod download; fi
COPY . .

# Build static binaries with security flags
# CGO_ENABLED=0: pure Go, no C dependencies
# -trimpath: remove local path information
# -ldflags='-s -w': strip debug info and symbol table
# Output goes under /work (writable by the builder user), not /bin.
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags='-s -w -X main.version=container' \
    -o /work/out/attackbox \
    ./cmd/attackbox

# Shipper stage: the shipper runs on the HOST, not in a container.
# Build only the binary and export it:
#   docker build --target shipper-export --output type=local,dest=./dist .
# Or build the image with `--target shipper` and copy /attackbox-shipper out.
FROM builder AS shipper-build
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags='-s -w -X main.version=container' \
    -o /work/out/attackbox-shipper \
    ./cmd/attackbox-shipper

FROM scratch AS shipper-export
COPY --from=shipper-build /work/out/attackbox-shipper /attackbox-shipper

FROM cgr.dev/chainguard/static@sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7 AS shipper
COPY --from=shipper-build /work/out/attackbox-shipper /attackbox-shipper
ENTRYPOINT ["/attackbox-shipper"]

# Runtime stage: Chainguard static (distroless, no shell)
# Verification: docker pull cgr.dev/chainguard/static:latest
# Command output: Digest: sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7
FROM cgr.dev/chainguard/static@sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7 AS bait

# Non-root UID/GID 65532 (Chainguard nonroot)
USER 65532:65532

COPY --from=builder --chown=65532:65532 /work/out/attackbox /attackbox

# Built-in healthcheck support via -healthcheck flag
ENTRYPOINT ["/attackbox"]
