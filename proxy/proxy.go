package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	proxyReadTimeout  = 30 * time.Second
	proxyWriteTimeout = 30 * time.Second
	dialTimeout       = 10 * time.Second
)

// upstreamTransport is the HTTP transport used to forward requests to the
// real upstream server after MITM interception.
var upstreamTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 20 * time.Second,
	MaxIdleConns:          256,
	MaxIdleConnsPerHost:   16,
	IdleConnTimeout:       90 * time.Second,
	// Trust the real server's cert — we are the client here.
	TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
}

// Proxy is the MITM HTTP/HTTPS proxy.
type Proxy struct {
	ca   *CA
	addr string
}

// New creates a Proxy listening on addr using ca for certificate signing.
func New(addr string, ca *CA) *Proxy {
	return &Proxy{addr: addr, ca: ca}
}

// ListenAndServe starts the proxy. It blocks until the server fails.
func (p *Proxy) ListenAndServe() error {
	srv := &http.Server{
		Addr:         p.addr,
		Handler:      p,
		ReadTimeout:  proxyReadTimeout,
		WriteTimeout: proxyWriteTimeout,
	}
	log.Printf("MITM proxy listening on %s", p.addr)
	return srv.ListenAndServe()
}

// ServeHTTP dispatches plain HTTP requests directly and HTTPS CONNECT tunnels
// through the MITM interceptor.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP handles plain HTTP (non-CONNECT) requests.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if IsAdRequest(r) {
		log.Printf("HTTP BLOCKED: %s %s", r.Method, r.URL)
		if err := drainRequestBody(r); err != nil {
			log.Printf("HTTP BLOCKED BODY DRAIN ERROR: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	r.RequestURI = ""
	stripHopHeaders(r.Header)

	resp, err := upstreamTransport.RoundTrip(r)
	if err != nil {
		log.Printf("HTTP FORWARD ERROR: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	stripHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleConnect intercepts HTTPS CONNECT tunnels, performs a TLS handshake
// with the client using a CA-signed cert, then forwards decrypted traffic.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	hostname, _, _ := net.SplitHostPort(host)

	// Acknowledge the CONNECT to the client.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("HIJACK ERROR: %v", err)
		return
	}
	defer clientConn.Close()

	_, err = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		log.Printf("CONNECT ACK ERROR: %v", err)
		return
	}

	// Wrap the client connection in TLS using a cert signed for this host.
	tlsCfg, err := p.ca.TLSConfigFor(hostname)
	if err != nil {
		log.Printf("CERT ERROR for %s: %v", hostname, err)
		return
	}

	tlsClient := tls.Server(clientConn, tlsCfg)
	if err := tlsClient.Handshake(); err != nil {
		// Common when a client rejects our CA cert — log at debug level only.
		log.Printf("TLS HANDSHAKE ERROR (%s): %v", hostname, err)
		return
	}
	defer tlsClient.Close()

	// Now read HTTP requests from the decrypted client stream.
	clientReader := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("READ REQUEST ERROR (%s): %v", hostname, err)
			}
			return
		}

		// Reconstruct the full URL so filters can inspect it.
		req.URL = &url.URL{
			Scheme:   "https",
			Host:     host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		req.RequestURI = ""
		req.Host = host

		if IsAdRequest(req) {
			log.Printf("HTTPS BLOCKED: %s %s", req.Method, req.URL)
			if err := drainRequestBody(req); err != nil {
				log.Printf("HTTPS BLOCKED BODY DRAIN ERROR (%s): %v", hostname, err)
				writeErrorResponse(tlsClient, req, http.StatusBadRequest)
				return
			}
			writeBlockedResponse(tlsClient, req)
			continue
		}

		log.Printf("HTTPS FORWARD: %s %s", req.Method, req.URL)
		if err := p.forwardRequest(tlsClient, req, host); err != nil {
			log.Printf("FORWARD ERROR (%s): %v", host, err)
			return
		}
	}
}

// forwardRequest sends req upstream and pipes the response back to the client.
func (p *Proxy) forwardRequest(clientConn net.Conn, req *http.Request, host string) error {
	stripHopHeaders(req.Header)
	sanitizeYouTubeResponse := shouldSanitizeYouTubeResponse(req)
	if sanitizeYouTubeResponse {
		req.Header.Del("Accept-Encoding")
	}

	resp, err := upstreamTransport.RoundTrip(req)
	if err != nil {
		writeErrorResponse(clientConn, req, http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	stripHopHeaders(resp.Header)
	if sanitizeYouTubeResponse {
		if err := sanitizeResponseBody(resp); err != nil {
			log.Printf("YOUTUBE RESPONSE SANITIZE ERROR (%s): %v", req.URL, err)
		}
	}

	// Use httputil to write a well-formed HTTP/1.1 response.
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	_, err = clientConn.Write(dump)
	return err
}

// writeBlockedResponse sends a 204 No Content back through the MITM connection.
// 204 is used instead of 403/444 so video players skip the ad silently
// rather than showing an error overlay.
func writeBlockedResponse(conn net.Conn, req *http.Request) {
	resp := &http.Response{
		StatusCode: http.StatusNoContent,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Length", "0")
	resp.Header.Set("Connection", "keep-alive")
	dump, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return
	}
	_, _ = conn.Write(dump)
}

func writeErrorResponse(conn net.Conn, req *http.Request, code int) {
	resp := &http.Response{
		StatusCode: code,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Request:    req,
	}
	dump, _ := httputil.DumpResponse(resp, false)
	_, _ = conn.Write(dump)
}

func drainRequestBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	_, copyErr := io.Copy(io.Discard, req.Body)
	closeErr := req.Body.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func shouldSanitizeYouTubeResponse(req *http.Request) bool {
	host := req.Host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	if host != "www.youtube.com" && host != "youtubei.googleapis.com" {
		return false
	}

	switch req.URL.Path {
	case "/youtubei/v1/player", "/youtubei/v1/next", "/youtubei/v1/get_watch":
		return true
	default:
		return false
	}
}

func sanitizeResponseBody(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}

	sanitized, changed, err := sanitizeYouTubeJSON(body)
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return err
	}
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(sanitized))
	resp.ContentLength = int64(len(sanitized))
	resp.Header.Set("Content-Length", fmt.Sprint(len(sanitized)))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-MD5")
	return nil
}

var youtubeAdResponseKeys = map[string]struct{}{
	"adbreakheartbeatparams":              {},
	"adbreakheartbeattiming":              {},
	"adbreakserviceparams":                {},
	"adplacements":                        {},
	"adparams":                            {},
	"adsignalsinfo":                       {},
	"adslots":                             {},
	"adtagparameters":                     {},
	"advideoid":                           {},
	"companionadconfig":                   {},
	"companionadslots":                    {},
	"instreamadslots":                     {},
	"playerads":                           {},
	"playerlegacydesktopypcofferrenderer": {},
	"promotedsparkleswebrenderer":         {},
}

func sanitizeYouTubeJSON(body []byte) ([]byte, bool, error) {
	var payload any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, false, err
	}

	changed := stripYouTubeAdFields(payload)
	if !changed {
		return body, false, nil
	}

	sanitized, err := json.Marshal(payload)
	if err != nil {
		return nil, false, err
	}
	return sanitized, true, nil
}

func stripYouTubeAdFields(v any) bool {
	changed := false

	switch value := v.(type) {
	case map[string]any:
		for key, child := range value {
			if _, ok := youtubeAdResponseKeys[strings.ToLower(key)]; ok {
				delete(value, key)
				changed = true
				continue
			}
			if stripYouTubeAdFields(child) {
				changed = true
			}
		}
	case []any:
		for _, child := range value {
			if stripYouTubeAdFields(child) {
				changed = true
			}
		}
	}

	return changed
}

// hopHeaders are removed before forwarding per RFC 7230.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

func stripHopHeaders(h http.Header) {
	for _, hdr := range hopHeaders {
		h.Del(hdr)
	}
	// Also strip headers listed in the Connection header value.
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(f))
		}
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// DialContext wraps the default dialer and can be extended to route traffic
// through a specific interface or upstream proxy if needed.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, addr)
}
