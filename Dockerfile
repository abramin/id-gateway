# Backend Dockerfile for ID Gateway
#
# Optimized for BuildKit caching and smaller layers.

# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install git for module fetching
RUN apk add --no-cache git

# Enable build caching for modules and compiled objects
ENV GOMODCACHE=/go/pkg/mod \
    GOCACHE=/root/.cache/go-build

# Pre-fetch dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy only source needed for backend build to keep layer cacheable
COPY cmd cmd
COPY internal internal
COPY pkg pkg

# Build the application
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o /build/id-gateway ./cmd/server

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /build/id-gateway .

# Expose port
EXPOSE 8080

# Run the application
CMD ["./id-gateway"]
