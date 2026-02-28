# Version defaults -- keep in sync with rust-toolchain.toml and go.mod
# Override at build time: docker build --build-arg RUST_VERSION=1.93 ...
ARG RUST_VERSION=1.92
ARG GO_VERSION=1.24

# Stage 1: Rust build
FROM --platform=$TARGETPLATFORM rust:${RUST_VERSION}-alpine AS rust-builder

RUN apk add --no-cache musl-dev perl make

# Install cbindgen for C header generation
RUN cargo install cbindgen

WORKDIR /rust

# Copy only the Rust crate (cache-friendly layer ordering)
COPY genesis-core/ .

# Build the static library with PQ features (cache mounts for faster rebuilds)
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release --features pq

# Generate C header
RUN cbindgen --config cbindgen.toml --output genesis_core.h

# Stage 2: Go build
ARG GO_VERSION
FROM --platform=$TARGETPLATFORM golang:${GO_VERSION}-alpine AS go-builder

ARG TARGETARCH

WORKDIR /workspace

# Install build dependencies for CGO
RUN apk add --no-cache git gcc musl-dev

# Copy the Rust static library and header from rust stage
COPY --from=rust-builder /rust/target/release/libgenesis_core.a /usr/local/lib/
COPY --from=rust-builder /rust/genesis_core.h /workspace/internal/bridge/genesis_core.h

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy Go source
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/

# Build arguments for version info
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Build the operator with CGO enabled (links against Rust static library)
RUN CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o manager ./cmd/operator

# Build the CLI with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o genesis ./cmd/genesis

# Stage 3: Runtime (distroless)
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source="https://github.com/LarsenClose/genesis-operator"
LABEL org.opencontainers.image.description="Genesis Operator - GitOps secrets bootstrap for Kubernetes"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /

COPY --from=go-builder /workspace/manager .
COPY --from=go-builder /workspace/genesis /usr/local/bin/genesis

USER 65532:65532

ENTRYPOINT ["/manager"]
