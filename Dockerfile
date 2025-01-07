# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

# Build Geth in a stock Go builder container
FROM golang:1.21-alpine as builder

RUN apk add --no-cache gcc musl-dev linux-headers git

# Set the working directory
WORKDIR /go-ethereum

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod .
COPY go.sum .
RUN go mod download

# Add source code and build
ADD . .
RUN go run build/ci.go install -static ./cmd/geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

# Create a user to run the service
RUN adduser -D -g '' appuser
USER appuser

COPY --from=builder /go-ethereum/build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["geth"]

# Add some metadata labels to help programatic image consumption
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM"
