package main

import (
	"bufio"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"

	"dnsproxy/proxy"
)

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

type blocklist struct {
	exact    map[string]struct{}
	suffixes []string
}

var builtInAdDomains = []string{
	"2mdn.net",
	"ad.doubleclick.net",
	"adservice.google.com",
	"adsrvr.org",
	"adsystem.com",
	"amazon-adsystem.com",
	"analytics.google.com",
	"app-measurement.com",
	"beacons.gcp.gvt2.com",
	"beacons.gvt2.com",
	"doubleclick.net",
	"google-analytics.com",
	"googleadservices.com",
	"googleads.g.doubleclick.net",
	"googlesyndication.com",
	"googletagmanager.com",
	"googletagservices.com",
	"imasdk.googleapis.com",
	"pagead2.googlesyndication.com",
	"scorecardresearch.com",
	"taboola.com",
	"tpc.googlesyndication.com",
	"video-ad-stats.googlevideo.com",
	"ad-creatives-public.googlevideo.com",
}

func loadBlocklist(path string) (*blocklist, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	bl := &blocklist{exact: make(map[string]struct{})}
	for _, domain := range builtInAdDomains {
		bl.add(domain)
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		domain, ok := parseBlocklistDomain(scanner.Text())
		if !ok {
			continue
		}
		bl.add(domain)
	}
	return bl, scanner.Err()
}

func parseBlocklistDomain(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "@@") {
		return "", false
	}
	if i := strings.IndexAny(line, "#!"); i != -1 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	if len(fields) > 1 {
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			line = fields[1]
		} else {
			line = fields[0]
		}
	}
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimPrefix(line, "|")
	if domain, _, ok := strings.Cut(line, "^"); ok {
		line = domain
	}
	if domain, _, ok := strings.Cut(line, "$"); ok {
		line = domain
	}
	line = strings.TrimPrefix(line, "*.")
	line = strings.TrimPrefix(line, ".")
	line = strings.TrimSuffix(line, ".")
	line = strings.ToLower(line)
	if line == "" || strings.ContainsAny(line, "/:*") {
		return "", false
	}
	if _, err := netip.ParseAddr(line); err == nil {
		return "", false
	}
	return line, true
}

func (bl *blocklist) add(domain string) {
	domain, ok := parseBlocklistDomain(domain)
	if !ok {
		return
	}
	bl.exact[domain] = struct{}{}
	bl.suffixes = append(bl.suffixes, domain)
}

func (bl *blocklist) isBlocked(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if _, ok := bl.exact[domain]; ok {
		return true
	}
	for _, suffix := range bl.suffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// DNS cache
// ---------------------------------------------------------------------------

type cacheItem struct {
	msg       *dns.Msg
	expiresAt time.Time
}

func cacheKey(name string, qtype uint16) string {
	return name + "|" + dns.TypeToString[qtype]
}

func copyMsg(m *dns.Msg) *dns.Msg { return m.Copy() }

const (
	defaultDNSAddr  = ":53"
	fallbackDNSAddr = ":53535"
	minTTL          = 10 * time.Second
	maxTTL          = 600 * time.Second
	defaultTTL      = 60 * time.Second
	cacheSize       = 4096
	clientTimeout   = 3 * time.Second
	upstream        = "8.8.8.8:53"
)

var dnsCache *lru.Cache[string, cacheItem]

func dnsListenAddr() string {
	if addr := strings.TrimSpace(os.Getenv("DNS_ADDR")); addr != "" {
		return addr
	}
	if os.Geteuid() != 0 {
		log.Printf("DNS :53 requires root; using %s. Set DNS_ADDR=:53 and run with sudo for real clients.", fallbackDNSAddr)
		return fallbackDNSAddr
	}
	return defaultDNSAddr
}

// ---------------------------------------------------------------------------
// MITM redirect: domains whose traffic we want to intercept via the proxy.
// The DNS handler returns the local machine IP for these, so HTTPS clients
// connect to our MITM proxy instead of the real server.
// ---------------------------------------------------------------------------

var mitmDomains = []string{
	// youtube.com — intercept ad API calls (/pagead/, /api/stats/ads, etc.)
	"youtube.com",
	"youtubei.googleapis.com",

	// Ad infrastructure — safe to MITM, only serves ads
	"imasdk.googleapis.com",
	"pagead2.googlesyndication.com",
	"ad.doubleclick.net",
	"static.doubleclick.net",
	"googleads.g.doubleclick.net",
	"ade.googlesyndication.com",
	"s0.2mdn.net",
	"s1.2mdn.net",
	"s2.2mdn.net",
	// YouTube ad and content media share googlevideo.com. We MITM it so the
	// proxy can block ad-tagged streams while allowing normal video streams.
	"googlevideo.com",
}

// localIP is the IP address of this machine on the network.
// Clients must use this machine as their DNS server AND HTTP/HTTPS proxy.
// Override with the LOCAL_IP environment variable if needed.
func localIP() net.IP {
	if v := os.Getenv("LOCAL_IP"); v != "" {
		if ip := net.ParseIP(v); ip != nil {
			return ip.To4()
		}
	}
	// Auto-detect: pick the first non-loopback IPv4 address.
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if v4 := ipnet.IP.To4(); v4 != nil {
					return v4
				}
			}
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

func isMITMDomain(domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	for _, d := range mitmDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func isMITMAddressQuery(qtype uint16) bool {
	return qtype == dns.TypeA || qtype == dns.TypeAAAA || qtype == dns.TypeHTTPS || qtype == dns.TypeSVCB
}

func writeNXDOMAIN(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeNameError
	if err := w.WriteMsg(m); err != nil {
		log.Println("WRITE ERROR:", err)
	}
}

func writeNODATA(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if err := w.WriteMsg(m); err != nil {
		log.Println("WRITE ERROR:", err)
	}
}

func writeLocalA(w dns.ResponseWriter, r *dns.Msg, q dns.Question, ip net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    10, // short TTL so clients pick up changes quickly
		},
		A: ip,
	})
	if err := w.WriteMsg(m); err != nil {
		log.Println("WRITE ERROR:", err)
	}
}

// ---------------------------------------------------------------------------
// DNS handler
// ---------------------------------------------------------------------------

func handleDNSRequest(bl *blocklist, myIP net.IP) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			return
		}

		q := r.Question[0]
		name := strings.TrimSuffix(q.Name, ".")

		// 1. Hard block — return NXDOMAIN.
		if bl.isBlocked(name) {
			log.Println("BLOCKED:", name)
			writeNXDOMAIN(w, r)
			return
		}

		// 2. MITM redirect — return our local IP so traffic hits the proxy.
		//    Suppress AAAA and HTTPS/SVCB records for these domains so clients
		//    do not bypass the local IPv4 MITM route via IPv6, HTTP/3, or ECH.
		if isMITMAddressQuery(q.Qtype) && isMITMDomain(name) {
			if q.Qtype == dns.TypeA {
				log.Println("MITM REDIRECT:", name, "→", myIP)
				writeLocalA(w, r, q, myIP)
			} else {
				log.Println("MITM SUPPRESS:", name, dns.TypeToString[q.Qtype])
				writeNODATA(w, r)
			}
			return
		}

		key := cacheKey(name, q.Qtype)

		// 3. Cache hit.
		if item, ok := dnsCache.Get(key); ok {
			if time.Now().Before(item.expiresAt) {
				log.Println("CACHE HIT:", name)
				reply := copyMsg(item.msg)
				reply.Id = r.Id
				if err := w.WriteMsg(reply); err != nil {
					log.Println("WRITE ERROR:", err)
				}
				return
			}
			dnsCache.Remove(key)
		}

		// 4. Forward to upstream.
		client := &dns.Client{Timeout: clientTimeout}
		resp, _, err := client.Exchange(r, upstream)
		if err != nil {
			log.Println("FORWARD ERROR:", err)
			m := new(dns.Msg)
			m.SetReply(r)
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
		if resp == nil {
			return
		}

		ttl := defaultTTL
		if len(resp.Answer) > 0 {
			ttl = time.Duration(resp.Answer[0].Header().Ttl) * time.Second
		}
		if ttl < minTTL {
			ttl = minTTL
		}
		if ttl > maxTTL {
			ttl = maxTTL
		}

		dnsCache.Add(key, cacheItem{msg: copyMsg(resp), expiresAt: time.Now().Add(ttl)})

		if err := w.WriteMsg(resp); err != nil {
			log.Println("WRITE ERROR:", err)
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// --- blocklist ---
	bl, err := loadBlocklist("blocklist.txt")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Blocklist: %d exact, %d suffix rules", len(bl.exact), len(bl.suffixes))

	// --- DNS cache ---
	dnsCache, err = lru.New[string, cacheItem](cacheSize)
	if err != nil {
		log.Fatal(err)
	}

	// --- CA for MITM ---
	ca, err := proxy.LoadOrCreateCA("ca.crt", "ca.key")
	if err != nil {
		log.Fatalf("CA error: %v", err)
	}
	log.Println("CA ready — install ca.crt as a trusted root on your devices")

	// --- local IP for MITM DNS redirect ---
	myIP := localIP()
	log.Printf("Local IP for MITM redirect: %s", myIP)

	// --- MITM proxy ---
	mitmProxy := proxy.New(":8080", ca)
	go func() {
		if err := mitmProxy.ListenAndServe(); err != nil {
			log.Fatalf("MITM proxy error: %v", err)
		}
	}()

	// --- DNS servers (UDP + TCP) ---
	handler := handleDNSRequest(bl, myIP)
	dns.HandleFunc(".", handler)
	dnsAddr := dnsListenAddr()

	startDNS := func(net string) {
		srv := &dns.Server{Addr: dnsAddr, Net: net}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("DNS %s error: %v", net, err)
		}
	}

	log.Printf("DNS server running on %s (udp+tcp)", dnsAddr)
	go startDNS("tcp")
	startDNS("udp")
}
