// metrics-gateway: cloud metrics collection and forwarding service.
//
// Accepts WebSocket connections on a configurable endpoint and processes
// incoming telemetry streams by routing them to the appropriate backend
// collectors based on routing metadata embedded in the payload.
//
// Environment variables:
//   SERVICE_HOST           listen address                      (default: 0.0.0.0)
//   PORT / SERVICE_PORT    listen port, PORT takes precedence  (default: 8080)
//   SERVICE_ENDPOINT       WebSocket endpoint path             (default: /api/v1/metrics)
//   SERVICE_TOKEN          authentication token (UUID format)  (required)
//   RESOLVER_PATH          DNS resolver endpoint path          (default: /dns-query, set "" to disable)
//   LOG_VERBOSE            set to any value to log stream targets (default: off)
//
// Build: go build -o metrics-gateway metrics-gateway.go

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxWSPayload caps the accepted WebSocket frame payload to prevent a
// malicious client from sending a 127-byte length header claiming 2^63 bytes
// and causing an immediate OOM on make([]byte, payloadLen).
const maxWSPayload = 16 << 20 // 16 MiB

// Connection management
const (
	maxConnections = 1024
	idleTimeout    = 5 * time.Minute
	// authTimeout bounds how long an upgraded connection may sit before
	// completing stream authentication. It exists separately from idleTimeout
	// because connections count against maxConnections from the moment they
	// upgrade, and unauthenticated clients have no legitimate reason to idle.
	authTimeout = 30 * time.Second
	dialTimeout = 15 * time.Second
)

var (
	// activeConns counts every hijacked WebSocket connection, including
	// upgraded-but-not-yet-authenticated ones, so unauthenticated clients
	// cannot exhaust file descriptors behind the connection cap.
	activeConns atomic.Int64
	startTime   = time.Now()

	// trackedWS holds every hijacked WebSocket connection so the shutdown
	// path can close them cleanly (http.Server does not track hijacked
	// connections). wsGroup lets shutdown wait for bridge goroutines to exit.
	trackedWS sync.Map // net.Conn -> struct{}
	wsGroup   sync.WaitGroup

	// verboseLogging enables per-stream target logging via LOG_VERBOSE.
	// PaaS platforms retain stdout logs, so routine traffic metadata — which
	// hosts and ports users contact — stays off by default.
	verboseLogging = os.Getenv("LOG_VERBOSE") != ""
)

// ── Concurrent WebSocket writer ───────────────────────────────────────────────
//
// wsWriter serialises all writes to a single WebSocket connection so that the
// two bridge goroutines (upstream data and ping-pong replies) never race on
// the underlying net.Conn. net.Conn is not goroutine-safe for concurrent
// writes; without this mutex frame boundaries corrupt under load.

type wsWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

func newWSWriter(conn net.Conn) *wsWriter { return &wsWriter{conn: conn} }

// writeFrame encodes data as a binary WebSocket frame and sends it atomically.
func (w *wsWriter) writeFrame(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeWSFrame(w.conn, data)
}

// pong sends a WebSocket pong control frame atomically.
func (w *wsWriter) pong(payload []byte) {
	if len(payload) > 125 {
		return
	}
	buf := make([]byte, 2+len(payload))
	buf[0] = 0x8a
	buf[1] = byte(len(payload))
	copy(buf[2:], payload)
	w.mu.Lock()
	w.conn.Write(buf) //nolint:errcheck
	w.mu.Unlock()
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	serviceHost := envOr("SERVICE_HOST", "0.0.0.0")
	// PaaS platforms assign the listen port through PORT at runtime; it must
	// win over any baked-in SERVICE_PORT default.
	servicePort := envOr("PORT", envOr("SERVICE_PORT", "8080"))
	serviceEndpoint := envOr("SERVICE_ENDPOINT", "/api/v1/metrics")
	resolverPath := envOr("RESOLVER_PATH", "/dns-query")
	listenAddr := serviceHost + ":" + servicePort

	// Reject path configs that would either not match or make ServeMux panic
	// on duplicate registration.
	for _, p := range []struct{ name, path string }{
		{"SERVICE_ENDPOINT", serviceEndpoint},
		{"RESOLVER_PATH", resolverPath},
	} {
		if p.path == "" {
			continue
		}
		if !strings.HasPrefix(p.path, "/") {
			log.Fatalf("[metrics] %s %q must start with /", p.name, p.path)
		}
		if p.path == "/" || p.path == "/health" {
			log.Fatalf("[metrics] %s %q conflicts with a built-in route", p.name, p.path)
		}
	}
	if resolverPath == serviceEndpoint {
		log.Fatalf("[metrics] RESOLVER_PATH %q conflicts with SERVICE_ENDPOINT", resolverPath)
	}

	token := os.Getenv("SERVICE_TOKEN")
	if token == "" {
		log.Fatal("[metrics] SERVICE_TOKEN is required")
	}
	authToken, err := parseUUID(token)
	if err != nil {
		log.Fatalf("[metrics] invalid SERVICE_TOKEN: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc(serviceEndpoint, makeHandler(authToken))
	mux.HandleFunc("/health", healthHandler)
	if resolverPath != "" {
		mux.HandleFunc(resolverPath, makeDNSHandler(authToken))
	}

	log.Printf("[metrics] listening  : %s", listenAddr)
	log.Printf("[metrics] endpoint   : %s", serviceEndpoint)
	if resolverPath != "" {
		log.Printf("[metrics] DNS resolver: https://<your-public-domain>%s", resolverPath)
	}

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: commonHeaders(mux),
		// Timeouts mirror a stock nginx front end: client_header_timeout 60s
		// (we stay a little tighter), keepalive_timeout 75s, and 8-16k header
		// buffers instead of Go's 1 MiB default. ReadTimeout/WriteTimeout only
		// affect requests before hijacking, so streaming sessions are exempt.
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// Go's http server logs client-side garbage (TLS probes, malformed
		// request lines) to the server error log; a real nginx deployment does
		// not surface those in stdout. Silence it to keep the log drain clean.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	// Heroku, Render, Railway, Fly.io all send SIGTERM and expect the process
	// to exit within ~30 s before they send SIGKILL. Order of operations:
	//   1. closeTrackedWS — send a WebSocket close frame to every hijacked
	//      session (they are outside http.Server's tracking) and close the
	//      underlying connections, unblocking all bridge goroutines;
	//   2. waitBridges — give sessions a short window to finish;
	//   3. srv.Shutdown — drain any remaining plain-HTTP requests.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Printf("[metrics] shutdown signal received, draining…")
		closeTrackedWS()
		waitBridges(10 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("[metrics] shutdown error: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[metrics] fatal: %v", err)
	}
	log.Printf("[metrics] stopped")
}

func trackWS(c net.Conn)   { trackedWS.Store(c, struct{}{}) }
func untrackWS(c net.Conn) { trackedWS.Delete(c) }

// closeTrackedWS sends a WebSocket close frame to every live session and then
// closes the underlying connection, unblocking all bridge goroutines.
func closeTrackedWS() {
	trackedWS.Range(func(key, _ any) bool {
		if c, ok := key.(net.Conn); ok {
			sendWSClose(c)
			c.Close()
			trackedWS.Delete(key)
		}
		return true
	})
}

// waitBridges blocks until every tracked session has exited or d elapses.
func waitBridges(d time.Duration) {
	done := make(chan struct{})
	go func() { wsGroup.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		log.Printf("[metrics] drain timeout reached, forcing exit")
	}
}

// commonHeaders is a thin middleware that stamps every non-hijacked HTTP
// response with headers a properly configured nginx reverse-proxy would add.
// This makes the service look like a standard cloud API at the HTTP layer.
func commonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Server", "nginx")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// nginxError writes an HTML error page shaped byte-for-byte like a stock nginx
// error page (server_tokens off), so error responses stay consistent with the
// "Server: nginx" header. Go's default http.Error plain-text bodies are a Go
// fingerprint that trivially breaks the cover story.
func nginxError(w http.ResponseWriter, code int) {
	msg := http.StatusText(code)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	fmt.Fprintf(w,
		"<html>\r\n<head><title>%d %s</title></head>\r\n"+
			"<body>\r\n<center><h1>%d %s</h1></center>\r\n"+
			"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
		code, msg, code, msg) //nolint:errcheck
}

// ── Health endpoint ───────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	// Signal to PaaS load balancers that this instance is saturated so they
	// stop routing new connections here (relevant if running multiple dynos).
	if activeConns.Load() >= maxConnections {
		nginxError(w, http.StatusServiceUnavailable)
		return
	}
	fmt.Fprintln(w, "ok")
}

// ── Index page ────────────────────────────────────────────────────────────────

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Meridian Cloud Services</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0e17;color:#c9d1d9;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{text-align:center;padding:3rem 2rem;max-width:480px}
.logo{font-size:2rem;font-weight:700;color:#58a6ff;margin-bottom:.5rem}
.tagline{color:#8b949e;font-size:.95rem;margin-bottom:2.5rem}
.status{display:inline-flex;align-items:center;gap:.5rem;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.6rem 1.2rem;font-size:.85rem}
.dot{width:8px;height:8px;border-radius:50%;background:#3fb950;display:inline-block}
.footer{margin-top:2.5rem;font-size:.75rem;color:#484f58}
</style>
</head>
<body>
<div class="card">
<div class="logo">Meridian Cloud Services</div>
<p class="tagline">Infrastructure metrics collection &amp; forwarding platform</p>
<div class="status"><span class="dot"></span> All systems operational</div>
<p class="footer">&copy; 2026 Meridian Cloud Services. Internal use only.</p>
</div>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		nginxError(w, http.StatusNotFound)
		return
	}
	// nginx serving a static page rejects everything that isn't GET/HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		nginxError(w, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(indexHTML)) //nolint:errcheck
}

// ── DNS resolver endpoint ─────────────────────────────────────────────────────

func makeDNSHandler(authToken []byte) http.HandlerFunc {
	upstreams := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	// Pre-compute the expected credential once at startup.
	authHex := hex.EncodeToString(authToken)
	return func(w http.ResponseWriter, r *http.Request) {
		// Require the same SERVICE_TOKEN as either:
		//   Authorization: Bearer <token-hex>
		//   ?token=<token-hex>
		// This prevents the endpoint being used as an open DNS relay, which
		// can get your server IP added to DNS-abuse blocklists.
		var provided string
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			provided = strings.TrimPrefix(auth, "Bearer ")
		} else {
			provided = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(authHex)) != 1 {
			nginxError(w, http.StatusUnauthorized)
			return
		}

		var (
			query []byte
			err   error
		)
		switch r.Method {
		case http.MethodGet:
			param := r.URL.Query().Get("dns")
			if param == "" {
				nginxError(w, http.StatusBadRequest)
				return
			}
			query, err = base64.RawURLEncoding.DecodeString(param)
			if err != nil || len(query) == 0 {
				nginxError(w, http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if !strings.Contains(r.Header.Get("Content-Type"), "application/dns-message") {
				nginxError(w, http.StatusUnsupportedMediaType)
				return
			}
			query, err = io.ReadAll(io.LimitReader(r.Body, 2048))
			if err != nil || len(query) == 0 {
				nginxError(w, http.StatusBadRequest)
				return
			}
		default:
			nginxError(w, http.StatusMethodNotAllowed)
			return
		}

		// DNS names cap at ~300 bytes over the wire; 2048 is generous. Beyond
		// that the exchange would corrupt anyway (DNS-over-TCP length prefixes
		// are 16-bit), so reject instead of truncating.
		if len(query) > 2048 {
			nginxError(w, http.StatusBadRequest)
			return
		}

		var resp []byte
		for _, upstream := range upstreams {
			if resp, err = dnsOverTCP(upstream, query); err == nil {
				break
			}
			log.Printf("[metrics] resolver upstream %s error: %v", upstream, err)
		}
		if err != nil {
			nginxError(w, http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		w.Write(resp) //nolint:errcheck
	}
}

func dnsOverTCP(server string, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 0xffff {
		return nil, fmt.Errorf("query length %d out of range for DNS-over-TCP", len(query))
	}
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	buf := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(buf, uint16(len(query)))
	copy(buf[2:], query)
	if _, err = conn.Write(buf); err != nil {
		return nil, err
	}

	var hdr [2]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ── Stream header parser ─────────────────────────────────────────────────────
//
// The payload header format (all multi-byte integers are big-endian):
//
//	Byte 0:      Version (must be 0)
//	Byte 1-16:   Authentication token (16-byte UUID)
//	Byte 17:     Extension length (0 for base streams)
//	Byte 18+:    Extension data (skipped when length is 0)
//	Next byte:   Operation (1=TCP stream, 2=UDP datagram)
//	Next 2:      Destination port
//	Next byte:   Address type (1=IPv4, 2=Domain, 3=IPv6)
//	Remaining:   Destination address:
//	               IPv4:   4 bytes
//	               Domain: 1 byte length + N bytes
//	               IPv6:   16 bytes
//
// After the header, raw payload data follows. The caller derives the header
// length from the reader's remaining bytes instead of re-parsing.

type routeHeader struct {
	command byte
	port    uint16
	addr    string
}

func parseRouteHeader(r io.Reader, expectedUUID []byte) (*routeHeader, error) {
	// Read version byte
	var ver [1]byte
	if _, err := io.ReadFull(r, ver[:]); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if ver[0] != 0 {
		return nil, fmt.Errorf("unsupported version: %d", ver[0])
	}

	// Read authentication token (16 bytes)
	var token [16]byte
	if _, err := io.ReadFull(r, token[:]); err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}

	if expectedUUID == nil {
		return nil, fmt.Errorf("token not configured")
	}
	if subtle.ConstantTimeCompare(token[:], expectedUUID) != 1 {
		return nil, fmt.Errorf("authentication failed")
	}

	// Read extension length and skip any extension bytes.
	var extLen [1]byte
	if _, err := io.ReadFull(r, extLen[:]); err != nil {
		return nil, fmt.Errorf("read extension length: %w", err)
	}
	if extLen[0] > 0 {
		ext := make([]byte, extLen[0])
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, fmt.Errorf("read extension data: %w", err)
		}
	}

	// Read operation byte.
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return nil, fmt.Errorf("read operation: %w", err)
	}
	if cmd[0] != 1 && cmd[0] != 2 {
		return nil, fmt.Errorf("unsupported operation: %d", cmd[0])
	}

	// Read port
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	// Read address type
	var addrType [1]byte
	if _, err := io.ReadFull(r, addrType[:]); err != nil {
		return nil, fmt.Errorf("read address type: %w", err)
	}

	var addr string
	switch addrType[0] {
	case 1: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, fmt.Errorf("read IPv4: %w", err)
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	case 2: // Domain
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		if dlen[0] == 0 || dlen[0] > 255 {
			return nil, fmt.Errorf("invalid domain length: %d", dlen[0])
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		addr = string(domain)
	case 3: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, fmt.Errorf("read IPv6: %w", err)
		}
		addr = net.IP(ip[:]).String()
	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType[0])
	}

	return &routeHeader{command: cmd[0], port: port, addr: addr}, nil
}

// ── Connection handler ───────────────────────────────────────────────────────

func makeHandler(authToken []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Validate GET method for WebSocket
		if r.Method != http.MethodGet {
			nginxError(w, http.StatusMethodNotAllowed)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			// Return plausible-looking metrics JSON to any HTTP scanner or
			// active prober that hits this path without a WebSocket upgrade.
			// A real metrics API would respond to GET with current counters.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-cache")
			fmt.Fprintf(w,
				`{"service":"metrics-gateway","version":"3.1.0","status":"operational","uptime_seconds":%d,"streams":{"active":%d,"total_ingested":0},"timestamp":"%s"}`,
				int64(time.Since(startTime).Seconds()),
				activeConns.Load(),
				time.Now().UTC().Format(time.RFC3339),
			)
			return
		}

		// Enforce connection limit. Because the counter includes upgraded-but-
		// not-yet-authenticated connections, unauthenticated floods trip this.
		if activeConns.Load() >= maxConnections {
			log.Printf("[metrics] capacity limit reached (%d)", maxConnections)
			nginxError(w, http.StatusServiceUnavailable)
			return
		}

		remote := realIP(r)

		wsConn, wsReader, err := upgradeWS(w, r)
		if err != nil {
			log.Printf("[metrics] upgrade error src=%s: %v", remote, err)
			return
		}
		defer wsConn.Close()

		// From here the connection is hijacked: count it, register it for the
		// shutdown path, and track the handler for the drain wait.
		activeConns.Add(1)
		defer activeConns.Add(-1)
		trackWS(wsConn)
		defer untrackWS(wsConn)
		wsGroup.Add(1)
		defer wsGroup.Done()

		// Wrap the connection in a mutex-protected writer now, since ping
		// replies may already race the caller's writes during stream setup.
		ww := newWSWriter(wsConn)

		// Bound how long a client may sit unauthenticated. After stream setup
		// the bridge installs idleTimeout instead.
		wsConn.SetReadDeadline(time.Now().Add(authTimeout)) //nolint:errcheck

		// Read the first data frame to get stream parameters. Control frames
		// (ping/pong) before it are answered and skipped.
		payload, err := readFirstDataFrame(wsReader, wsConn, ww)
		if err != nil {
			if err != errClientClosed {
				log.Printf("[metrics] stream init error src=%s: %v", remote, err)
				sendWSClose(wsConn)
			}
			return
		}
		if len(payload) < 22 { // minimum header size
			log.Printf("[metrics] stream header malformed src=%s len=%d", remote, len(payload))
			sendWSClose(wsConn)
			return
		}

		br := bytes.NewReader(payload)
		hdr, err := parseRouteHeader(br, authToken)
		if err != nil {
			log.Printf("[metrics] stream setup failed src=%s: %v", remote, err)
			sendWSClose(wsConn)
			return
		}
		// Bytes consumed by the header = total frame minus what the reader
		// has left. Anything after it is stream data.
		headerLen := len(payload) - br.Len()

		// Resolve and validate destination (SSRF protection).
		target, err := resolveAndCheckTarget(hdr.addr, fmt.Sprintf("%d", hdr.port))
		if err != nil {
			log.Printf("[metrics] target rejected src=%s: %v", remote, err)
			if verboseLogging {
				log.Printf("[metrics] rejected target addr=%s src=%s", hdr.addr, remote)
			}
			sendWSClose(wsConn)
			return
		}
		log.Printf("[metrics] stream authorized src=%s op=%d", remote, hdr.command)
		if verboseLogging {
			log.Printf("[metrics] upstream=%s op=%d src=%s", target, hdr.command, remote)
		}

		// Clear deadline before bridging (bridge sets its own)
		wsConn.SetReadDeadline(time.Time{}) //nolint:errcheck

		switch hdr.command {
		case 1: // TCP
			targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
			if err != nil {
				log.Printf("[metrics] upstream dial error src=%s: %v", remote, err)
				sendWSClose(wsConn)
				return
			}
			defer targetConn.Close()
			// Disable Nagle's algorithm so small writes (HTTP headers, SSH
			// keystrokes, API requests) are sent immediately instead of being
			// held for up to 40 ms waiting for an ACK from the remote side.
			if tc, ok := targetConn.(*net.TCPConn); ok {
				tc.SetNoDelay(true) //nolint:errcheck
			}

			// Send stream acknowledgement: protocol version + no extensions.
			if werr := ww.writeFrame([]byte{0x00, 0x00}); werr != nil {
				log.Printf("[metrics] stream ack error src=%s: %v", remote, werr)
				return
			}

			// Flush any payload bytes that followed the stream header.
			if headerLen < len(payload) {
				if _, err := targetConn.Write(payload[headerLen:]); err != nil {
					log.Printf("[metrics] stream flush error src=%s: %v", remote, err)
					return
				}
			}

			bridgeTCP(ww, wsReader, targetConn)

		case 2: // UDP
			targetAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				log.Printf("[metrics] datagram resolve error src=%s: %v", remote, err)
				sendWSClose(wsConn)
				return
			}
			targetConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				log.Printf("[metrics] datagram upstream error src=%s: %v", remote, err)
				sendWSClose(wsConn)
				return
			}
			defer targetConn.Close()

			// Send stream acknowledgement: protocol version + no extensions.
			if werr := ww.writeFrame([]byte{0x00, 0x00}); werr != nil {
				log.Printf("[metrics] datagram ack error src=%s: %v", remote, werr)
				return
			}

			// Flush initial datagrams that followed the stream header.
			forwardDatagrams(targetConn, payload[headerLen:])

			bridgeUDP(ww, wsReader, targetConn)
		}
	}
}

var errClientClosed = fmt.Errorf("client closed before stream setup")

// readFirstDataFrame reads frames until a data frame (continuation, text, or
// binary) arrives, replying to pings and ignoring pongs. Returns the data
// frame's payload. errClientClosed signals a clean close before setup.
func readFirstDataFrame(wsReader *bufio.Reader, conn net.Conn, ww *wsWriter) ([]byte, error) {
	for {
		payload, opcode, err := readWSFrame(wsReader)
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x0, 0x1, 0x2: // data frame carrying the stream header
			return payload, nil
		case 0x8: // clean close before stream setup
			return nil, errClientClosed
		case 0x9: // ping → pong, keep waiting
			ww.pong(payload)
			conn.SetReadDeadline(time.Now().Add(authTimeout)) //nolint:errcheck
		}
		// 0xA (unsolicited pong): ignore.
	}
}

// ── TCP bridge ───────────────────────────────────────────────────────────────

func bridgeTCP(ww *wsWriter, wsReader *bufio.Reader, targetConn net.Conn) {
	done := make(chan struct{}, 2)
	resetDeadline := func() {
		deadline := time.Now().Add(idleTimeout)
		ww.conn.SetDeadline(deadline)    //nolint:errcheck
		targetConn.SetDeadline(deadline) //nolint:errcheck
	}
	resetDeadline()

	// WS → Target: unwrap WebSocket frames, write raw bytes to target
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			payload, opcode, err := readWSFrame(wsReader)
			if err != nil {
				return
			}
			switch opcode {
			case 0x0, 0x1, 0x2: // continuation, text, binary
				if len(payload) > 0 {
					if _, werr := targetConn.Write(payload); werr != nil {
						return
					}
					resetDeadline()
				}
			case 0x8: // close
				return
			case 0x9: // ping → pong (serialised through mutex)
				ww.pong(payload)
			}
		}
	}()

	// Target → WS: read raw bytes from target, wrap in binary WebSocket frames
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if werr := ww.writeFrame(buf[:n]); werr != nil {
					return
				}
				resetDeadline()
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	ww.conn.Close()
	targetConn.Close()
	<-done
}

// ── UDP bridge ───────────────────────────────────────────────────────────────
//
// WebSocket frames carry length-prefixed UDP datagrams:
//
//	[2-byte big-endian length][datagram payload] × N
//
// A single frame may pack several datagrams back-to-back; forward them all.
func bridgeUDP(ww *wsWriter, wsReader *bufio.Reader, targetConn *net.UDPConn) {
	done := make(chan struct{}, 2)
	resetDeadline := func() {
		deadline := time.Now().Add(idleTimeout)
		ww.conn.SetDeadline(deadline)    //nolint:errcheck
		targetConn.SetDeadline(deadline) //nolint:errcheck
	}
	resetDeadline()

	// WS → Target: unpack every datagram in each frame
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			payload, opcode, err := readWSFrame(wsReader)
			if err != nil {
				return
			}
			switch opcode {
			case 0x0, 0x1, 0x2:
				forwardDatagrams(targetConn, payload)
				resetDeadline()
			case 0x8:
				return
			case 0x9:
				ww.pong(payload)
			}
		}
	}()

	// Target → WS: each UDP datagram gets length-prefixed and wrapped in a frame
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				frame := make([]byte, 2+n)
				binary.BigEndian.PutUint16(frame, uint16(n))
				copy(frame[2:], buf[:n])
				if werr := ww.writeFrame(frame); werr != nil {
					return
				}
				resetDeadline()
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	ww.conn.Close()
	targetConn.Close()
	<-done
}

// forwardDatagrams parses and sends every length-prefixed datagram packed
// into buf, stopping at a truncated tail (never a valid datagram).
func forwardDatagrams(conn *net.UDPConn, buf []byte) {
	for len(buf) >= 2 {
		n := int(binary.BigEndian.Uint16(buf[:2]))
		if n > len(buf)-2 {
			break
		}
		conn.Write(buf[2 : 2+n]) //nolint:errcheck
		buf = buf[2+n:]
	}
}

// ── WebSocket framing (RFC 6455) ─────────────────────────────────────────────

func upgradeWS(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.Reader, error) {
	// RFC 6455 §4.2.1: version must be 13.
	if r.Header.Get("Sec-Websocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		nginxError(w, http.StatusBadRequest)
		return nil, nil, fmt.Errorf("websocket version not 13")
	}

	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		nginxError(w, http.StatusBadRequest)
		return nil, nil, fmt.Errorf("missing Sec-WebSocket-Key header")
	}

	h := sha1.New()
	io.WriteString(h, key+wsGUID) //nolint:errcheck
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		nginxError(w, http.StatusInternalServerError)
		return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
	}

	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("hijack: %w", err)
	}

	// Build the 101 response.  Include Server header so the upgrade response
	// matches what the rest of the service advertises.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Server: nginx\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n"

	// Echo the first requested sub-protocol if the client sent one.
	// Echoing it makes the handshake indistinguishable from a real
	// application-level WebSocket (e.g. a chat or STOMP endpoint).
	if proto := r.Header.Get("Sec-Websocket-Protocol"); proto != "" {
		first, _, _ := strings.Cut(proto, ",")
		resp += "Sec-WebSocket-Protocol: " + strings.TrimSpace(first) + "\r\n"
	}
	resp += "\r\n"

	if _, err = io.WriteString(rw, resp); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write 101: %w", err)
	}
	if err = rw.Flush(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("flush 101: %w", err)
	}

	return conn, rw.Reader, nil
}

func sendWSClose(conn net.Conn) {
	conn.Write([]byte{0x88, 0x00}) //nolint:errcheck
}

func readWSFrame(r io.Reader) ([]byte, byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, err
	}

	// RSV1/RSV2/RSV3 must be zero — we negotiate no extensions.
	// RFC 6455 §5.2: a peer that receives a frame with RSV bits set that it
	// did not agree to via extension negotiation must close the connection.
	if hdr[0]&0x70 != 0 {
		return nil, 0, fmt.Errorf("ws: reserved bits set (0x%02x)", hdr[0])
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0f

	// Only data and the three control opcodes are defined; anything else is a
	// protocol error (RFC 6455 §5.2), and control frames must not be
	// fragmented (§5.4).
	switch opcode {
	case 0x0, 0x1, 0x2:
	case 0x8, 0x9, 0xa:
		if !fin {
			return nil, 0, fmt.Errorf("ws: fragmented control frame (opcode 0x%x)", opcode)
		}
	default:
		return nil, 0, fmt.Errorf("ws: unknown opcode 0x%x", opcode)
	}

	// RFC 6455 §5.1: the server must close the connection on receiving an
	// unmasked frame from a client. Tolerating it is both a spec violation
	// and a differentiator strict probers can poke at.
	hasMask := hdr[1]>>7 == 1
	if !hasMask {
		return nil, 0, fmt.Errorf("ws: unmasked client frame")
	}

	payloadLen := uint64(hdr[1] & 0x7f)
	switch payloadLen {
	case 126:
		var ext uint16
		if err := binary.Read(r, binary.BigEndian, &ext); err != nil {
			return nil, 0, err
		}
		payloadLen = uint64(ext)
	case 127:
		if err := binary.Read(r, binary.BigEndian, &payloadLen); err != nil {
			return nil, 0, err
		}
	}

	// RFC 6455 §5.5: control frames carry at most 125 bytes; a close frame
	// with a lone byte of payload is invalid (no complete status code).
	if opcode >= 0x8 {
		if payloadLen > 125 {
			return nil, 0, fmt.Errorf("ws: control frame payload too large: %d", payloadLen)
		}
		if opcode == 0x8 && payloadLen == 1 {
			return nil, 0, fmt.Errorf("ws: close frame with 1-byte payload")
		}
	}

	if payloadLen > maxWSPayload {
		return nil, 0, fmt.Errorf("ws frame payload too large: %d bytes (max %d)", payloadLen, maxWSPayload)
	}

	var mask [4]byte
	if _, err := io.ReadFull(r, mask[:]); err != nil {
		return nil, 0, err
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}

	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return payload, opcode, nil
}

// writeWSFrame encodes data as a single RFC 6455 binary frame and writes it
// in one syscall.  Splitting header and payload into two Write calls can
// produce two TCP segments, making the frame boundary visible in a packet
// capture and adding unnecessary latency.
func writeWSFrame(w io.Writer, data []byte) error {
	l := len(data)
	var hdrLen int
	switch {
	case l <= 125:
		hdrLen = 2
	case l <= 65535:
		hdrLen = 4
	default:
		hdrLen = 10
	}

	frame := make([]byte, hdrLen+l)
	frame[0] = 0x82 // FIN + binary opcode
	switch hdrLen {
	case 2:
		frame[1] = byte(l)
	case 4:
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:], uint16(l))
	case 10:
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:], uint64(l))
	}
	copy(frame[hdrLen:], data)

	_, err := w.Write(frame)
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// realIP extracts the originating client IP from the request.
// On PaaS platforms (Heroku, Render, Railway, Fly.io) RemoteAddr is always
// the internal load-balancer address; the real client IP is the first entry
// in X-Forwarded-For (or X-Real-IP as a fallback).
func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseUUID converts a UUID string (with or without dashes) to 16 raw bytes.
func parseUUID(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return nil, fmt.Errorf("UUID must be 32 hex characters (got %d)", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return b, nil
}

// blockedPorts are destination ports the gateway refuses to proxy to.
// Port 25 is the classic abuse vector: letting a PaaS workload originate
// SMTP traffic is the fastest route to a provider ban.
var blockedPorts = map[string]struct{}{"25": {}}

// blockedPrefixes are address ranges not covered by netip.Addr.IsPrivate but
// still unsuitable as external stream targets.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT / carrier internal (RFC 6598)
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking (RFC 2544)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments (RFC 6890)
}

// isBlockedIP reports whether an IP is loopback, link-local (which covers the
// cloud metadata address 169.254.169.254), private, unspecified, multicast,
// or in one of blockedPrefixes. IPv4-mapped IPv6 addresses are normalised
// first so ::ffff:127.0.0.1 cannot smuggle a blocked v4 address past the check.
func isBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveAndCheckTarget resolves a host:port, checks for blocked IPs, and returns
// the resolved address suitable for dialing. Returns error if the target is blocked.
func resolveAndCheckTarget(host, port string) (string, error) {
	if _, blocked := blockedPorts[port]; blocked {
		return "", fmt.Errorf("destination port %s blocked", port)
	}

	// If host is already an IP, check directly
	if ip, err := netip.ParseAddr(host); err == nil {
		if isBlockedIP(ip) {
			return "", fmt.Errorf("blocked target address")
		}
		return net.JoinHostPort(host, port), nil
	}

	// Resolve domain and check all resolved IPs. The checked address itself is
	// what's dialed (not a re-resolved one), so no DNS-rebind TOCTOU gap.
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("dns lookup: %w", err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses found for %s", host)
	}
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok && isBlockedIP(addr) {
			return "", fmt.Errorf("blocked target address")
		}
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
