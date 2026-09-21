# Multi-stage Dockerfile to build SPIRE oidc-discovery-provider binary from source
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
RUN git clone --depth 1 --branch v1.15.2 https://github.com/spiffe/spire.git .
WORKDIR /src/support/oidc-discovery-provider
ENV GOTOOLCHAIN=auto
RUN CGO_ENABLED=0 go build -o /bin/oidc-discovery-provider .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /bin/oidc-discovery-provider /usr/local/bin/oidc-discovery-provider

EXPOSE 8008

ENTRYPOINT ["/usr/local/bin/oidc-discovery-provider"]
CMD ["-config", "/etc/spire/oidc-discovery-provider.conf"]
