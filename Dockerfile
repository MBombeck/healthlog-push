# Builder runs on the build host and cross-compiles for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /src

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . .
# scripts/build.sh is the one build recipe; the release binaries are built with it too, so the binary in
# this image and the release binary of the same tag are the same file (docs/verify.md).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    sh scripts/build.sh "$VERSION" "$COMMIT" "$TARGETARCH" /out/healthlog-push

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
