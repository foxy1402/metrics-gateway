// metrics-gateway: cloud metrics collection and forwarding service.
//
// Accepts WebSocket connections on a configurable endpoint and processes
// incoming telemetry streams by routing them to the appropriate backend
// collectors based on routing metadata embedded in the payload.
//
// Environment variables:
//   SERVICE_HOST              listen address                     (default: 0.0.0.0)
//   SERVICE_PORT / PORT       listen port                        (default: 8080)
//   SERVICE_ENDPOINT          WebSocket endpoint path             (default: /api/v1/metrics)
//   SERVICE_TOKEN             authentication token (UUID format) (required)
//   RESOLVER_PATH             DNS resolver endpoint path         (default: /dns-query, set "" to disable)
//
// Cloudflare Tunnel sidecar (docker-compose only — not used by this binary):
//   CLOUDFLARE_TUNNEL_TOKEN   tunnel token from the Cloudflare dashboard; when set
//                             the cloudflared sidecar creates an outbound-only tunnel
//                             so no public port binding is required (default: disabled)
//
// Build: go build -o metrics-gateway metrics-gateway.go

package main

import (
	"bufio"
	"bytes"
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
	"strings"
	"sync/atomic"
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
var activeConns atomic.Int64

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
		mux.HandleFunc(resolverPath, makeDNSHandler())
	}

	log.Printf("[metrics] listening  : %s", listenAddr)
	log.Printf("[metrics] endpoint   : %s", serviceEndpoint)
	if resolverPath != "" {
		log.Printf("[metrics] DNS resolver: https://<your-public-domain>%s", resolverPath)
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[metrics] fatal: %v", err)
	}
}

// ── Health endpoint ───────────────────────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
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
<p class="footer">&copy; 2024 Meridian Cloud Services. Internal use only.</p>
</div>
</body>
</html>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(indexHTML)) //nolint:errcheck
}

// ── DNS resolver endpoint ─────────────────────────────────────────────────────

func makeDNSHandler() http.HandlerFunc {
	upstreams := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53"}
	return func(w http.ResponseWriter, r *http.Request) {
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

// ── Routing protocol parser ──────────────────────────────────────────────────
//
// The payload header format (all multi-byte integers are big-endian):
//
//   Byte 0:      Version (must be 0)
//   Byte 1-16:   Authentication token (16-byte UUID)
//   Byte 17:     Addon length (0 for standard routing)
//   Byte 18+:    Addon data (skipped, length from byte 17)
//   Next byte:   Command (1=TCP stream, 2=UDP relay)
//   Next 2:      Target port
//   Next byte:   Address type (1=IPv4, 2=Domain, 3=IPv6)
//   Remaining:   Target address:
//                  IPv4:   4 bytes
//                  Domain: 1 byte length + N bytes
//                  IPv6:   16 bytes
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

	// Read addon length and skip addon data
	var addonLen [1]byte
	if _, err := io.ReadFull(r, addonLen[:]); err != nil {
		return nil, fmt.Errorf("read addon length: %w", err)
	}
	if addonLen[0] > 0 {
		addon := make([]byte, addonLen[0])
		if _, err := io.ReadFull(r, addon); err != nil {
			return nil, fmt.Errorf("read addon: %w", err)
		}
	}

	// Read command
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return nil, fmt.Errorf("read command: %w", err)
	}
	if cmd[0] != 1 && cmd[0] != 2 {
		return nil, fmt.Errorf("unsupported command: %d", cmd[0])
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
			http.NotFound(w, r)
			return
		}

		// Enforce connection limit
		if activeConns.Load() >= maxConnections {
			log.Printf("[metrics] connection rejected: limit reached (%d)", maxConnections)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		remote := r.RemoteAddr
		log.Printf("[metrics] connection established remote=%s", remote)

		wsConn, wsReader, err := upgradeWS(w, r)
		if err != nil {
			log.Printf("[metrics] connection upgrade error remote=%s: %v", remote, err)
			return
		}
		defer wsConn.Close()

		// Set idle timeout on first frame read
		wsConn.SetReadDeadline(time.Now().Add(idleTimeout)) //nolint:errcheck

		// Read first frame to get routing header
		payload, opcode, err := readWSFrame(wsReader)
		if err != nil {
			log.Printf("[metrics] read first frame error remote=%s: %v", remote, err)
			sendWSClose(wsConn)
			return
		}
		if opcode == 0x8 { // close frame
			return
		}
		if len(payload) < 22 { // minimum header size
			log.Printf("[metrics] payload too short remote=%s len=%d", remote, len(payload))
			sendWSClose(wsConn)
			return
		}

		hdr, err := parseRouteHeader(bytes.NewReader(payload), authToken)
		if err != nil {
			log.Printf("[metrics] header parse error remote=%s: %v", remote, err)
			sendWSClose(wsConn)
			return
		}

		// Resolve and validate target (SSRF protection)
		target, err := resolveAndCheckTarget(hdr.addr, fmt.Sprintf("%d", hdr.port))
		if err != nil {
			log.Printf("[metrics] target blocked remote=%s addr=%s: %v", remote, hdr.addr, err)
			sendWSClose(wsConn)
			return
		}
		log.Printf("[metrics] routing to %s (cmd=%d) remote=%s", target, hdr.command, remote)

		// Track connection
		activeConns.Add(1)
		defer activeConns.Add(-1)

		// Clear deadline before bridging (bridge sets its own)
		wsConn.SetReadDeadline(time.Time{}) //nolint:errcheck

		switch hdr.command {
		case 1: // TCP
			targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
			if err != nil {
				log.Printf("[metrics] target connection error remote=%s target=%s: %v", remote, target, err)
				sendWSClose(wsConn)
				return
			}
			defer targetConn.Close()

			// Send VLESS response header: version(0) + addon_len(0)
			if werr := writeWSFrame(wsConn, []byte{0x00, 0x00}); werr != nil {
				log.Printf("[metrics] response header write error remote=%s: %v", remote, werr)
				return
			}

			// Write any remaining data from the first frame after the header
			headerLen := computeHeaderLen(payload)
			if headerLen < len(payload) {
				if _, err := targetConn.Write(payload[headerLen:]); err != nil {
					log.Printf("[metrics] initial write error remote=%s: %v", remote, err)
					return
				}
			}

			log.Printf("[metrics] session active remote=%s target=%s", remote, target)
			bridgeTCP(wsConn, wsReader, targetConn)
			log.Printf("[metrics] session closed remote=%s", remote)

		case 2: // UDP
			targetAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				log.Printf("[metrics] UDP resolve error remote=%s target=%s: %v", remote, target, err)
				sendWSClose(wsConn)
				return
			}
			targetConn, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				log.Printf("[metrics] UDP dial error remote=%s target=%s: %v", remote, target, err)
				sendWSClose(wsConn)
				return
			}
			defer targetConn.Close()

			// Send VLESS response header: version(0) + addon_len(0)
			if werr := writeWSFrame(wsConn, []byte{0x00, 0x00}); werr != nil {
				log.Printf("[metrics] UDP response header write error remote=%s: %v", remote, werr)
				return
			}

			// Write initial UDP datagram (strip length prefix from first frame)
			headerLen := computeHeaderLen(payload)
			remaining := payload[headerLen:]
			if len(remaining) >= 2 {
				dgramLen := binary.BigEndian.Uint16(remaining[:2])
				if int(dgramLen) <= len(remaining)-2 {
					targetConn.Write(remaining[2 : 2+dgramLen]) //nolint:errcheck
				}
			}

			log.Printf("[metrics] UDP session active remote=%s target=%s", remote, target)
			bridgeUDP(wsConn, wsReader, targetConn)
			log.Printf("[metrics] UDP session closed remote=%s", remote)
		}
	}
}

// computeHeaderLen calculates the byte length of the routing header in a payload.
func computeHeaderLen(payload []byte) int {
	// version(1) + token(16) + addon_len(1) = offset 18
	if len(payload) < 18 {
		return len(payload)
	}
	addonLen := int(payload[17])
	offset := 18 + addonLen // skip addon data

	// command(1) + port(2) + addrType(1) = 4 more bytes
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

func bridgeTCP(wsConn net.Conn, wsReader *bufio.Reader, targetConn net.Conn) {
	done := make(chan struct{}, 2)
	resetDeadline := func() {
		deadline := time.Now().Add(idleTimeout)
		wsConn.SetDeadline(deadline)     //nolint:errcheck
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
			case 0x9: // ping → reply pong
				if len(payload) <= 125 {
					pong := append([]byte{0x8a, byte(len(payload))}, payload...)
					wsConn.Write(pong) //nolint:errcheck
				}
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
				if werr := writeWSFrame(wsConn, buf[:n]); werr != nil {
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
	wsConn.Close()
	targetConn.Close()
	<-done
}

// ── UDP bridge ───────────────────────────────────────────────────────────────
//
// Each WebSocket frame contains one UDP datagram (length-prefixed):
//   [2-byte big-endian length][datagram payload]

func bridgeUDP(wsConn net.Conn, wsReader *bufio.Reader, targetConn *net.UDPConn) {
	done := make(chan struct{}, 2)
	resetDeadline := func() {
		deadline := time.Now().Add(idleTimeout)
		wsConn.SetDeadline(deadline)     //nolint:errcheck
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
				if len(payload) <= 125 {
					pong := append([]byte{0x8a, byte(len(payload))}, payload...)
					wsConn.Write(pong) //nolint:errcheck
				}
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
				if werr := writeWSFrame(wsConn, frame); werr != nil {
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
	wsConn.Close()
	targetConn.Close()
	<-done
}

// ── WebSocket framing (RFC 6455) ─────────────────────────────────────────────

func upgradeWS(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.Reader, error) {
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

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"

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

func writeWSFrame(w io.Writer, data []byte) error {
	l := len(data)
	var hdr []byte
	switch {
	case l <= 125:
		hdr = []byte{0x82, byte(l)}
	case l <= 65535:
		hdr = []byte{0x82, 126, byte(l >> 8), byte(l & 0xff)}
	default:
		hdr = make([]byte, 10)
		hdr[0] = 0x82
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
