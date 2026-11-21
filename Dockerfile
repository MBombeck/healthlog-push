# syntax=docker/dockerfile:1

# Builder runs on the build host and cross-compiles for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath \
      -ldflags "-s -w -buildid= \
        -X github.com/MBombeck/healthlog-push/internal/buildinfo.Version=${VERSION} \
        -X github.com/MBombeck/healthlog-push/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/healthlog-push ./cmd/healthlog-push

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.source="https://github.com/MBombeck/healthlog-push" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.description="Push relay for the HealthLog app" \
      org.opencontainers.image.title="healthlog-push" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

COPY --from=build /out/healthlog-push /healthlog-push

USER 65532:65530
ENTRYPOINT ["/healthlog-push"]
CMD ["relay"]
