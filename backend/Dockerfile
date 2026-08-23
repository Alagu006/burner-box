# ---- Build stage ----
FROM golang:1.23-alpine AS builder

RUN apk --no-cache add git

WORKDIR /app

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /server ./cmd/server

# ---- Runtime stage ----
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

# Non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /server .
COPY --from=builder /app/docs ./docs

# Persistent uploads directory (mounted as Fly volume)
RUN mkdir -p uploads/submissions && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/api/health || exit 1

CMD ["./server"]
