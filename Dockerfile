# Descles edge: the open-core data plane only (no hosted control-plane code).
# Build:  docker build -t descles/edge .
# Use:    descles edge init --image descles/edge   (or the published, digest-pinned image)

FROM golang:1.27-alpine AS build
ARG GOPROXY=https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN GOPROXY=$GOPROXY go mod download
COPY . .
RUN CGO_ENABLED=0 GOPROXY=$GOPROXY go build -trimpath -ldflags="-s -w" -o /descles-edge ./cmd/edge

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -u 10001 descles && \
    mkdir -p /data && chown descles:descles /data
USER descles
COPY --from=build /descles-edge /usr/local/bin/descles-edge
VOLUME ["/data"]
WORKDIR /data
ENV DESCLES_MODE=edge DESCLES_STORAGE=sqlite DESCLES_SQLITE_PATH=/data/spans.db
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/descles-edge"]
