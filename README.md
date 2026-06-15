# Metrics Gateway

A lightweight, zero-dependency WebSocket gateway for real-time metrics collection and forwarding. Accepts authenticated WebSocket connections and routes telemetry streams to the appropriate backend over TCP or UDP.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Deployment](#deployment)
  - [Docker Compose](#docker-compose)
  - [Docker (standalone)](#docker-standalone)
  - [Build from Source](#build-from-source)
  - [Heroku / Render / Railway](#heroku--render--railway)
- [Cloudflare Tunnel](#cloudflare-tunnel)
  - [Why Use It](#why-use-it)
  - [1. Create the Tunnel](#1-create-the-tunnel)
  - [2. Configure Public Hostname](#2-configure-public-hostname)
  - [3. Add the Token to Your Deployment](#3-add-the-token-to-your-deployment)
  - [4. Remove the Direct Port Binding](#4-remove-the-direct-port-binding)
  - [Verifying the Tunnel](#verifying-the-tunnel)
- [Endpoints](#endpoints)
- [Security Notes](#security-notes)

---

## Quick Start

The only two variables you must set are `SERVICE_TOKEN` and `SERVICE_ENDPOINT`.

```env
SERVICE_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890
SERVICE_ENDPOINT=/mysecret8765
```

`SERVICE_TOKEN` is the UUID that clients must present to authenticate. Generate one with:

```sh
# Linux / macOS
cat /proc/sys/kernel/random/uuid
# or
uuidgen
```

`SERVICE_ENDPOINT` is the WebSocket path clients connect to. Use something non-guessable — treat it as a second layer of access control.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SERVICE_TOKEN` | **Yes** | — | UUID authentication token. Clients must include this in every connection. |
| `SERVICE_ENDPOINT` | No | `/api/v1/metrics` | WebSocket endpoint path. Use a secret path in production. |
| `SERVICE_HOST` | No | `0.0.0.0` | Address the server binds to. |
| `SERVICE_PORT` / `PORT` | No | `8080` | TCP port to listen on. `PORT` takes precedence (used by Heroku/Render). |
| `RESOLVER_PATH` | No | `/dns-query` | Path for the built-in DNS-over-HTTPS resolver. Set to `""` to disable it entirely. |
| `CLOUDFLARE_TUNNEL_TOKEN` | No | *(disabled)* | Cloudflare Tunnel token. When set, the `cloudflared` sidecar activates and creates an outbound-only tunnel. See [Cloudflare Tunnel](#cloudflare-tunnel). |

---

## Deployment

### Docker Compose

This is the recommended approach. Create a `.env` file next to `docker-compose.yml`:

```env
SERVICE_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890
SERVICE_ENDPOINT=/mysecret8765
```

Then bring the stack up:

```sh
docker compose up -d
```

The service will be available at `ws://your-host:8080/mysecret8765`.

To verify it is healthy:

```sh
docker compose ps
curl http://localhost:8080/health
```

---

### Docker (standalone)

```sh
docker run -d \
  --name metrics-gateway \
  --restart unless-stopped \
  -p 8080:8080 \
  -e SERVICE_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -e SERVICE_ENDPOINT=/mysecret8765 \
  $(docker build -q .)
```

---

### Build from Source

Requires Go 1.22 or later.

```sh
go build -trimpath -ldflags="-s -w" -o metrics-gateway metrics-gateway.go

SERVICE_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
SERVICE_ENDPOINT=/mysecret8765 \
./metrics-gateway
```

---

### Heroku / Render / Railway

Set the environment variables in the platform dashboard or CLI and deploy directly. The service reads `PORT` automatically, so no extra configuration is needed for the port.

**Heroku example:**

```sh
heroku config:set SERVICE_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890
heroku config:set SERVICE_ENDPOINT=/mysecret8765
git push heroku main
```

The included `Procfile` handles the startup command.

---

## Cloudflare Tunnel

### Why Use It

By default the service binds a host port (`8080`) so it is reachable from the internet directly. Cloudflare Tunnel is an alternative that:

- Creates an **outbound-only** connection from your server to Cloudflare's edge — no inbound ports need to be open on your firewall or VPS.
- Puts your traffic behind Cloudflare's global network (DDoS protection, TLS termination, access policies).
- Works on servers where you **cannot** bind public ports (shared hosting, NAT environments, locked-down VMs).
- Gives you a stable `*.trycloudflare.com` or custom domain without touching DNS manually.

---

### 1. Create the Tunnel

1. Go to [Cloudflare Zero Trust](https://one.dash.cloudflare.com/) → **Networks → Tunnels**.
2. Click **Create a tunnel**, choose **Cloudflared**, and give it a name (e.g. `metrics-gateway`).
3. Cloudflare will display a tunnel token that looks like:

   ```
   eyJhIjoiZDFjYjA4ZTI1YWU2MDM2OWZjMjA...
   ```

   Copy it — you will need it in step 3.

> You do not need to run the install commands shown on that screen. The Docker sidecar handles everything.

---

### 2. Configure Public Hostname

Still on the tunnel configuration screen, go to the **Public Hostname** tab and add a route:

| Field | Value |
|---|---|
| **Subdomain** | anything you want, e.g. `gateway` |
| **Domain** | your Cloudflare-managed domain, e.g. `example.com` |
| **Type** | `HTTP` |
| **URL** | `metrics-gateway:8080` |

This tells cloudflared to forward incoming HTTPS/WebSocket traffic from `gateway.example.com` to the gateway container on its internal Docker network address. Save the configuration.

> **No domain?** Use a Quick Tunnel for testing: start the tunnel once manually with `docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token <YOUR_TOKEN>` and Cloudflare will assign a free `*.trycloudflare.com` hostname automatically. Quick Tunnels expire after a few hours and are not suitable for production.

---

### 3. Add the Token to Your Deployment

Add `CLOUDFLARE_TUNNEL_TOKEN` to your `.env` file alongside the existing variables:

```env
SERVICE_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890
SERVICE_ENDPOINT=/mysecret8765
CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoiZDFjYjA4ZTI1YWU2MDM2OWZjMjA...
```

Then restart the stack:

```sh
docker compose up -d
```

The `cloudflared` sidecar will start, connect to Cloudflare's edge, and log something like:

```
[tunnel] Registered tunnel connection connIndex=0 ...
```

---

### 4. Remove the Direct Port Binding

Once the tunnel is confirmed working you no longer need the host port exposed. Open `docker-compose.yml` and comment out or delete the `ports` block under `metrics-gateway`:

```yaml
  metrics-gateway:
    # ports:          # ← remove or comment out when using Cloudflare Tunnel
    #   - "8080:8080"
```

Restart once more:

```sh
docker compose up -d
```

The service is now only reachable through the Cloudflare edge. No port `8080` is accessible from outside the host.

---

### Verifying the Tunnel

Check that cloudflared connected successfully:

```sh
# Live logs from the sidecar
docker compose logs -f cloudflared

# Confirm the gateway is reachable through the tunnel
curl https://gateway.example.com/health
# → ok
```

In the Cloudflare Zero Trust dashboard under **Networks → Tunnels** the tunnel status should show **Healthy**.

---

## Endpoints

| Path | Description |
|---|---|
| `/` | Status page (HTML). Returns a generic service landing page. |
| `/health` | Health check. Returns `ok` with HTTP 200. Used by Docker and load balancers. |
| `$SERVICE_ENDPOINT` | WebSocket endpoint. Authenticated connections are handled here. |
| `/dns-query` | DNS-over-HTTPS resolver (RFC 8484). Supports GET and POST. Disable by setting `RESOLVER_PATH=""`. |

---

## Security Notes

- **Use a non-guessable `SERVICE_ENDPOINT`.**  
  The path acts as an additional access layer on top of the token. Something like `/mysecret8765` or a random slug is far harder to discover than the default `/api/v1/metrics`.

- **Rotate `SERVICE_TOKEN` if it is ever exposed.**  
  It is a standard UUID. Generate a new one and redeploy; old tokens are rejected immediately.

- **Prefer Cloudflare Tunnel over direct port binding in production.**  
  Removing the `ports` mapping eliminates the direct attack surface entirely. All traffic flows through Cloudflare's edge, which provides TLS, rate limiting, and DDoS mitigation at no extra cost.

- **The DNS resolver is outbound-only.**  
  It forwards queries to `8.8.8.8`, `1.1.1.1`, and `8.8.4.4` over TCP. If you do not need it, disable it with `RESOLVER_PATH=""`.

- **Connection limits are enforced in-process.**  
  The server caps concurrent WebSocket sessions at 1 024 and drops idle connections after 5 minutes.
