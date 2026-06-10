#!/bin/sh
PORT="${PORT:-${SERVICE_PORT:-8080}}"
HEX_PORT=$(printf '%04X' "$PORT")

if awk -v p="$HEX_PORT" '
    NR > 1 {
        split($2, a, ":")
        if (toupper(a[2]) == p && $4 == "0A") {
            found = 1
        }
    }
    END { exit(found ? 0 : 1) }
' /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
    echo "Health check passed"
    exit 0
fi

echo "Port ${PORT} not listening"
exit 1