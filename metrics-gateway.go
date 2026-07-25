// metrics-gateway: cloud metrics collection and forwarding service.
//
// Accepts WebSocket connections on a configurable endpoint and processes
// incoming telemetry streams by routing them to the appropriate backend
// collectors based on routing metadata embedded in the payload.
//
// Environment variables:
//   SERVICE_HOST           listen address                     (default: 0.0.0.0)
//   SERVICE_PORT / PORT    listen port                        (default: 8080)
//   SERVICE_ENDPOINT       WebSocket endpoint path             (default: /api/v1/metrics)
//   SERVICE_TOKEN          authentication token (UUID format) (required)
//   RESOLVER_PATH          DNS resolver endpoint path         (default: /dns-query, set "" to disable)
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
	dialTimeout    = 15 * time.Second
)

// activeConns tracks the number of currently active WebSocket sessions.
var (
	activeConns atomic.Int64
	startTime   = time.Now()
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
	servicePort := envOr("SERVICE_PORT", envOr("PORT", "8080"))
	serviceEndpoint := envOr("SERVICE_ENDPOINT", "/api/v1/metrics")
	resolverPath := envOr("RESOLVER_PATH", "/dns-query")
	listenAddr := serviceHost + ":" + servicePort

	if resolverPath != "" && resolverPath == serviceEndpoint {
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
		Addr:              listenAddr,
		Handler:           commonHeaders(mux),
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Graceful shutdown on SIGTERM / SIGINT.
	// Heroku, Render, Railway, Fly.io all send SIGTERM and expect the process
	// to exit within ~30 s before they send SIGKILL. We give srv.Shutdown 25 s
	// so the OS has a small buffer. Hijacked WebSocket connections are outside
	// http.Server's tracking and will be hard-closed by SIGKILL; for a
	// single-user service this is acceptable.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Printf("[metrics] shutdown signal received, draining…")
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
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

// ── Health endpoint ───────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	// Signal to PaaS load balancers that this instance is saturated so they
	// stop routing new connections here (relevant if running multiple dynos).
	if activeConns.Load() >= maxConnections {
		http.Error(w, "at capacity", http.StatusServiceUnavailable)
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
		http.NotFound(w, r)
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
			http.Error(w, "unauthorized", http.StatusUnauthorized)
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
				http.Error(w, "missing dns parameter", http.StatusBadRequest)
				return
			}
			query, err = base64.RawURLEncoding.DecodeString(param)
			if err != nil {
				http.Error(w, "invalid dns parameter", http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if !strings.Contains(r.Header.Get("Content-Type"), "application/dns-message") {
				http.Error(w, "content-type must be application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			query, err = io.ReadAll(io.LimitReader(r.Body, 2048))
			if err != nil || len(query) == 0 {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
			http.Error(w, "all resolver upstreams failed", http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		w.Write(resp) //nolint:errcheck
	}
}

func dnsOverTCP(server string, query []byte) ([]byte, error) {
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
// After the header, raw payload data follows.

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
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			// Return plausible-looking metrics JSON to any HTTP scanner or
			// active prober that hits this path without a WebSocket upgrade.
			// A real metrics API would respond to GET with current counters.
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-cache")
			fmt.Fprintf(w,
				`{"service":"metrics-gateway","version":"3.0.0","status":"operational","uptime_seconds":%d,"streams":{"active":%d,"total_ingested":0},"timestamp":"%s"}`,
				int64(time.Since(startTime).Seconds()),
				activeConns.Load(),
				time.Now().UTC().Format(time.RFC3339),
			)
			return
		}

		// Enforce connection limit
		if activeConns.Load() >= maxConnections {
			log.Printf("[metrics] capacity limit reached (%d)", maxConnections)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		remote := realIP(r)
		log.Printf("[metrics] client connected src=%s", remote)

		wsConn, wsReader, err := upgradeWS(w, r)
		if err != nil {
			log.Printf("[metrics] upgrade error src=%s: %v", remote, err)
			return
		}
		defer wsConn.Close()

		// Set idle timeout on first frame read
		wsConn.SetReadDeadline(time.Now().Add(idleTimeout)) //nolint:errcheck

		// Read first frame to get stream parameters.
		payload, opcode, err := readWSFrame(wsReader)
		if err != nil {
			log.Printf("[metrics] stream init error src=%s: %v", remote, err)
			sendWSClose(wsConn)
			return
		}
		if opcode == 0x8 { // close frame
			return
		}
		if len(payload) < 22 { // minimum header size
			log.Printf("[metrics] stream header malformed src=%s len=%d", remote, len(payload))
			sendWSClose(wsConn)
			return
		}

		hdr, err := parseRouteHeader(bytes.NewReader(payload), authToken)
		if err != nil {
			log.Printf("[metrics] stream setup failed src=%s: %v", remote, err)
			sendWSClose(wsConn)
			return
		}

		// Resolve and validate destination (SSRF protection).
		target, err := resolveAndCheckTarget(hdr.addr, fmt.Sprintf("%d", hdr.port))
		if err != nil {
			log.Printf("[metrics] upstream unavailable src=%s addr=%s: %v", remote, hdr.addr, err)
			sendWSClose(wsConn)
			return
		}
		log.Printf("[metrics] upstream=%s op=%d src=%s", target, hdr.command, remote)

		// Track connection
		activeConns.Add(1)
		defer activeConns.Add(-1)

		// Clear deadline before bridging (bridge sets its own)
		wsConn.SetReadDeadline(time.Time{}) //nolint:errcheck

		// Wrap the connection in a mutex-protected writer now that two goroutines
		// will write concurrently (data forwarding + ping-pong replies).
		ww := newWSWriter(wsConn)

		switch hdr.command {
		case 1: // TCP
			targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
			if err != nil {
				log.Printf("[metrics] upstream error src=%s upstream=%s: %v", remote, target, err)
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
			headerLen := computeHeaderLen(payload)
			if headerLen < len(payload) {
				if _, err := targetConn.Write(payload[headerLen:]); err != nil {
					log.Printf("[metrics] stream flush error src=%s: %v", remote, err)
					return
				}
			}

			log.Printf("[metrics] stream open src=%s upstream=%s", remote, target)
			bridgeTCP(ww, wsReader, targetConn)
			log.Printf("[metrics] stream closed src=%s", remote)

		case 2: // UDP
			targetAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				log.Printf("[metrics] datagram resolve error src=%s addr=%s: %v", remote, target, err)
				sendWSClose(wsConn)
				return
			}
			targetConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				log.Printf("[metrics] datagram upstream error src=%s addr=%s: %v", remote, target, err)
				sendWSClose(wsConn)
				return
			}
			defer targetConn.Close()

			// Send stream acknowledgement: protocol version + no extensions.
			if werr := ww.writeFrame([]byte{0x00, 0x00}); werr != nil {
				log.Printf("[metrics] datagram ack error src=%s: %v", remote, werr)
				return
			}

			// Flush initial datagram bytes that followed the stream header.
			headerLen := computeHeaderLen(payload)
			remaining := payload[headerLen:]
			if len(remaining) >= 2 {
				dgramLen := binary.BigEndian.Uint16(remaining[:2])
				if int(dgramLen) <= len(remaining)-2 {
					targetConn.Write(remaining[2 : 2+dgramLen]) //nolint:errcheck
				}
			}

			log.Printf("[metrics] datagram open src=%s upstream=%s", remote, target)
			bridgeUDP(ww, wsReader, targetConn)
			log.Printf("[metrics] datagram closed src=%s", remote)
		}
	}
}

// computeHeaderLen calculates the byte length of the routing header in a payload.
func computeHeaderLen(payload []byte) int {
	// version(1) + token(16) + ext_len(1) = offset 18
	if len(payload) < 18 {
		return len(payload)
	}
	extLen := int(payload[17])
	offset := 18 + extLen // skip extension bytes

	// operation(1) + port(2) + addrType(1) = 4 more bytes
	offset += 4
	if offset > len(payload) {
		return len(payload)
	}
	addrType := payload[offset-1]
	switch addrType {
	case 1: // IPv4
		offset += 4
	case 2: // Domain
		if offset < len(payload) {
			offset += 1 + int(payload[offset])
		}
	case 3: // IPv6
		offset += 16
	}
	return offset
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
// Each WebSocket frame contains one UDP datagram (length-prefixed):
//
//	[2-byte big-endian length][datagram payload]
func bridgeUDP(ww *wsWriter, wsReader *bufio.Reader, targetConn *net.UDPConn) {
	done := make(chan struct{}, 2)
	resetDeadline := func() {
		deadline := time.Now().Add(idleTimeout)
		ww.conn.SetDeadline(deadline)    //nolint:errcheck
		targetConn.SetDeadline(deadline) //nolint:errcheck
	}
	resetDeadline()

	// WS → Target: each frame is a length-prefixed UDP datagram
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			payload, opcode, err := readWSFrame(wsReader)
			if err != nil {
				return
			}
			switch opcode {
			case 0x0, 0x1, 0x2:
				if len(payload) < 2 {
					continue
				}
				dgramLen := binary.BigEndian.Uint16(payload[:2])
				if int(dgramLen) > len(payload)-2 {
					continue
				}
				targetConn.Write(payload[2 : 2+dgramLen]) //nolint:errcheck
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

// ── WebSocket framing (RFC 6455) ─────────────────────────────────────────────

func upgradeWS(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.Reader, error) {
	// RFC 6455 §4.2.1: version must be 13.
	if r.Header.Get("Sec-Websocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "websocket version 13 required", http.StatusBadRequest)
		return nil, nil, fmt.Errorf("websocket version not 13")
	}

	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, nil, fmt.Errorf("missing Sec-WebSocket-Key header")
	}

	h := sha1.New()
	io.WriteString(h, key+wsGUID) //nolint:errcheck
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
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
	opcode := hdr[0] & 0x0f
	hasMask := hdr[1]>>7 == 1
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

	if payloadLen > maxWSPayload {
		return nil, 0, fmt.Errorf("ws frame payload too large: %d bytes (max %d)", payloadLen, maxWSPayload)
	}

	var mask [4]byte
	if hasMask {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return nil, 0, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}

	if hasMask {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
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

// isBlockedAddr checks whether a resolved address is in a blocked range
// (loopback, link-local, private RFC1918, cloud metadata, unspecified).
func isBlockedAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false // not an IP, let the dialer handle DNS errors
	}
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		// Cloud metadata endpoint: 169.254.169.254
		ip == netip.MustParseAddr("169.254.169.254")
}

// resolveAndCheckTarget resolves a host:port, checks for blocked IPs, and returns
// the resolved address suitable for dialing. Returns error if the target is blocked.
func resolveAndCheckTarget(host, port string) (string, error) {
	// If host is already an IP, check directly
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
			ip == netip.MustParseAddr("169.254.169.254") {
			return "", fmt.Errorf("blocked target address")
		}
		return net.JoinHostPort(host, port), nil
	}

	// Resolve domain and check all resolved IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("dns lookup: %w", err)
	}
	for _, ip := range ips {
		if isBlockedAddr(ip.String()) {
			return "", fmt.Errorf("blocked target address")
		}
	}
	// Use the first resolved IP
	if len(ips) == 0 {
		return "", fmt.Errorf("no addresses found for %s", host)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
