# Build stage: use Go 1.22 on Alpine Linux.
FROM golang:1.22-alpine AS builder
# Install git (if needed) and other dependencies.
RUN apk add --no-cache git
WORKDIR /app
# Copy go.mod and go.sum and download dependencies.
COPY go.mod go.sum ./
RUN go mod download
# Copy the remaining source code.
COPY . .
# Build the binary statically.
RUN CGO_ENABLED=0 GOOS=linux go build -a -o webserver .

# Final stage: use a minimal scratch image.
FROM scratch
# Copy the built binary from the builder stage.
COPY --from=builder /app/webserver /webserver
# Expose the port your webserver listens on.
EXPOSE 8080
# Run the webserver binary.
ENTRYPOINT ["/webserver"]

