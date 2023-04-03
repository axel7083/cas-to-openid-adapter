# Stage 1: Build using GoLand image
FROM golang:1.18.10-bullseye as build

WORKDIR /app

# Copy source code into container
COPY . .

# Build the Go binary
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o myapp .

# Stage 2: Execute using Alpine-based image
FROM alpine:latest

WORKDIR /app

# Copy the binary from the build stage into the Alpine-based image
COPY --from=build /app/myapp .

# Set ownership and executable permissions on the binary
RUN chmod +x myapp

# Start the binary
CMD ["./myapp"]