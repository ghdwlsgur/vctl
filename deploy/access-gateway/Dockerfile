FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/vctl-access-gateway ./cmd/vctl-access-gateway
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/vctl-agent ./cmd/vctl-agent

FROM scratch
COPY --from=build /out/vctl-access-gateway /usr/local/bin/vctl-access-gateway
COPY --from=build /out/vctl-agent /usr/local/bin/vctl-agent
USER 65532:65532
ENV HOME=/home/nonroot
EXPOSE 8080
# Health is the kubelet's job: k8s.yaml probes /healthz on this port. scratch
# has no shell or HTTP client for a Docker HEALTHCHECK to run, so say so
# explicitly rather than leave it unset.
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/vctl-access-gateway"]
