# Multi-stage build for minimal production image
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Copy dependency definitions and source code
COPY go.mod ./
COPY internal/ ./internal/
COPY main.go ./
COPY index.html ./

# Build optimized static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/web-analyzer main.go

# Minimal final stage
FROM alpine:3.19

WORKDIR /app

# Add CA certificates for secure TLS/SSL inspection requests
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/web-analyzer /app/web-analyzer
COPY index.html /app/index.html

# Expose default port
EXPOSE 8080

# Environment defaults
ENV PORT=8080

# Run application
ENTRYPOINT ["/app/web-analyzer"]
CMD ["-serve"]
