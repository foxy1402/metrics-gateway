FROM golang:1.22-bookworm AS builder
WORKDIR /build
COPY go.mod ./
COPY metrics-gateway.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o metrics-gateway metrics-gateway.go

FROM debian:13-slim

LABEL org.opencontainers.image.title="Cloud Metrics Gateway"
LABEL org.opencontainers.image.description="Real-time metrics collection and forwarding service."
LABEL org.opencontainers.image.version="3.0.0"
LABEL service.type="metrics-gateway"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

COPY --from=builder /build/metrics-gateway /usr/local/bin/metrics-gateway
COPY start.sh /app/service-start.sh
COPY healthcheck.sh /app/service-healthcheck.sh

RUN chmod +x /usr/local/bin/metrics-gateway /app/service-start.sh /app/service-healthcheck.sh && \
    useradd -r -u 1000 -s /bin/false appuser && \
    chown -R appuser:appuser /app

ENV SERVICE_HOST=0.0.0.0 \
    SERVICE_PORT=8080 \
    SERVICE_ENDPOINT=/api/v1/metrics \
    SERVICE_TOKEN=

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD /app/service-healthcheck.sh || exit 1

USER appuser

CMD ["/app/service-start.sh"]