# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/raksa-netguard \
    ./cmd/raksa-netguard

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/raksa-netguard /raksa-netguard
USER nonroot:nonroot

ENTRYPOINT ["/raksa-netguard"]
CMD ["help"]
