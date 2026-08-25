#!/bin/sh
set -eu

log() { printf '[metrics] %s\n' "$*" >&2; }

# PaaS platforms assign the listen port via PORT at runtime; it must win over
# any baked-in default. Resolve here and export — without the export the
# child process never sees the resolved value.
SERVICE_HOST="${SERVICE_HOST:-0.0.0.0}"
SERVICE_PORT="${PORT:-${SERVICE_PORT:-8080}}"
SERVICE_ENDPOINT="${SERVICE_ENDPOINT:-/api/v1/metrics}"
export SERVICE_HOST SERVICE_PORT SERVICE_ENDPOINT

if [ -z "${SERVICE_TOKEN:-}" ]; then
    log "SERVICE_TOKEN is required"
    exit 1
fi

if ! printf '%s' "$SERVICE_PORT" | grep -Eq '^[0-9]+$' || \
   [ "$SERVICE_PORT" -lt 1 ] || [ "$SERVICE_PORT" -gt 65535 ]; then
    log "Invalid SERVICE_PORT: $SERVICE_PORT"
    exit 1
fi

if [ "${SERVICE_ENDPOINT#"/"}" = "$SERVICE_ENDPOINT" ]; then
    SERVICE_ENDPOINT="/$SERVICE_ENDPOINT"
    export SERVICE_ENDPOINT
fi

log "Starting metrics agent: endpoint=${SERVICE_HOST}:${SERVICE_PORT}${SERVICE_ENDPOINT}"
exec /usr/local/bin/metrics-gateway
