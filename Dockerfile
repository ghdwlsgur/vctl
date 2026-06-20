# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.4

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vctl ./cmd/vctl

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="vctl"
LABEL org.opencontainers.image.description="Vault-backed infrastructure access CLI"
LABEL org.opencontainers.image.source="https://github.com/ghdwlsgur/vctl"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=build /out/vctl /usr/local/bin/vctl

USER nonroot:nonroot
HEALTHCHECK --interval=5m --timeout=3s CMD ["/usr/local/bin/vctl", "--version"]
ENTRYPOINT ["/usr/local/bin/vctl"]
