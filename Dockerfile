# Stage 1: Rust build
FROM --platform=$TARGETPLATFORM rust:1.92-alpine AS rust-builder

RUN apk add --no-cache musl-dev perl make

# Install cbindgen for C header generation
RUN cargo install cbindgen

WORKDIR /rust

# Copy only the Rust crate (cache-friendly layer ordering)
COPY genesis-core/ .

# Build the static library
RUN cargo build --release

# Generate C header
RUN cbindgen --config cbindgen.toml --output genesis_core.h

# Stage 2: Go build
FROM --platform=$TARGETPLATFORM golang:1.24-alpine AS go-builder

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

WORKDIR /

COPY --from=go-builder /workspace/manager .
COPY --from=go-builder /workspace/genesis /usr/local/bin/genesis

USER 65532:65532

ENTRYPOINT ["/manager"]
