package proxy

import (
	"net/http"
	"strings"
)

// adPatterns are URL path/query substrings that identify YouTube ad requests.
// These are matched against the full request URL after MITM decryption.
var adPatterns = []string{
	// Ad serving API endpoints
	"/pagead/",
	"/api/stats/ads",
	"/get_video_info",
	"/youtubei/v1/log_event",
	"/youtubei/v1/player/ad_break",

	// DoubleClick / programmatic
	"/ddm/",
	"/td/",
	"/adi/",
	"/adj/",
	"/activityi;",

	// Ad measurement and verification
	"/pagead/adview",
	"/pagead/conversion",
	"/pagead/lvz",
	"/pagead/viewthroughconversion",
	"/pcs/activeview",

	// IMA SDK loader paths (belt-and-suspenders — DNS blocks the host too)
	"/ima/",
	"/instream/ad/",

	// YouTube ad slot identifiers in query strings
	"adformat=",
	"adunit=",
	"ad_type=",
	"ad_cpn=",
	"ad_id=",
	"ad_len=",
	"ad_mt=",
	"ad_playback=",
	"ad_sys=",
	"adslot=",
	"adsense_video_doc_id=",
	"is_ad=1",
	"pltype=adhost",
}

// adQueryKeys are query parameter names whose presence marks an ad request.
var adQueryKeys = []string{
	"ad_type",
	"adformat",
	"adunit",
	"ad_cpn",
	"ad_id",
	"ad_len",
	"ad_mt",
	"ad_playback",
	"ad_sys",
	"adsense_video_doc_id",
	"correlator",  // IMA correlation ID — only present in ad requests
	"rmktEnabled", // remarketing flag
	"afv_ad_tag",
}

// adHosts are hosts where every request is an ad/tracking request,
// complementing DNS blocking (catches cases where DNS cache is warm).
var adHosts = []string{
	"imasdk.googleapis.com",
	"pagead2.googlesyndication.com",
	"adservice.google.com",
	"ad.doubleclick.net",
	"googleads.g.doubleclick.net",
	"static.doubleclick.net",
	"cm.g.doubleclick.net",
	"stats.g.doubleclick.net",
	"survey.g.doubleclick.net",
	"ade.googlesyndication.com",
	"tpc.googlesyndication.com",
	"s0.2mdn.net",
	"s1.2mdn.net",
	"s2.2mdn.net",
	"video-ad-stats.googlevideo.com",
	"ad-creatives-public.googlevideo.com",
	"fundingchoicesmessages.google.com",
}

// IsAdRequest returns true if the request should be blocked.
func IsAdRequest(req *http.Request) bool {
	host := req.Host
	// strip port
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}

	// Full-host block
	for _, h := range adHosts {
		if host == h {
			return true
		}
	}

	rawURL := req.URL.String()

	// Path/URL substring match
	for _, pattern := range adPatterns {
		if strings.Contains(rawURL, pattern) {
			return true
		}
	}

	// Query key match
	q := req.URL.Query()
	for _, key := range adQueryKeys {
		if _, ok := q[key]; ok {
			return true
		}
	}

	// YouTube-specific: video requests with ad parameters
	// googlevideo.com serves both real video and ad video segments.
	// Ad segments have "ctier=A" or "oad" in the URL.
	if strings.HasSuffix(host, "googlevideo.com") {
		// Ad segments are identified by these URL markers
		if strings.Contains(rawURL, "ctier=L") ||
			strings.Contains(rawURL, "ctier=A") ||
			strings.Contains(rawURL, "&oad") ||
			strings.Contains(rawURL, "?oad") {
			return true
		}
		return false // real video — let through
	}

	return false
}
