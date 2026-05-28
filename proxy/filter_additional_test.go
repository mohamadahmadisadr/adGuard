package proxy

import (
	"testing"
)

func TestIsAdRequestBlocksAdHostsSingleChar(t *testing.T) {
	req := mustRequest(t, "GET", "https://imasdk.googleapis.com/path")
	if !IsAdRequest(req) {
		t.Fatal("expected imasdk.googleapis.com to be blocked")
	}
}

func TestIsAdRequestBlocksDoubleClickNetworks(t *testing.T) {
	adHosts := []string{
		"ad.doubleclick.net",
		"googleads.g.doubleclick.net",
		"static.doubleclick.net",
		"cm.g.doubleclick.net",
		"stats.g.doubleclick.net",
		"survey.g.doubleclick.net",
	}

	for _, host := range adHosts {
		t.Run(host, func(t *testing.T) {
			req := mustRequest(t, "GET", "https://"+host+"/request")
			if !IsAdRequest(req) {
				t.Errorf("expected %s to be blocked", host)
			}
		})
	}
}

func TestIsAdRequestBlocksGoogleSyndicationHosts(t *testing.T) {
	hosts := []string{
		"pagead2.googlesyndication.com",
		"ade.googlesyndication.com",
		"tpc.googlesyndication.com",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			req := mustRequest(t, "GET", "https://"+host+"/request")
			if !IsAdRequest(req) {
				t.Errorf("expected %s to be blocked", host)
			}
		})
	}
}

func TestIsAdRequestBlocksVideoAdStats(t *testing.T) {
	req := mustRequest(t, "GET", "https://video-ad-stats.googlevideo.com/data")
	if !IsAdRequest(req) {
		t.Fatal("expected video-ad-stats.googlevideo.com to be blocked")
	}
}

func TestIsAdRequestBlocksAdCreativePublic(t *testing.T) {
	req := mustRequest(t, "GET", "https://ad-creatives-public.googlevideo.com/file")
	if !IsAdRequest(req) {
		t.Fatal("expected ad-creatives-public.googlevideo.com to be blocked")
	}
}

func TestIsAdRequestBlocksFundingChoices(t *testing.T) {
	req := mustRequest(t, "GET", "https://fundingchoicesmessages.google.com/data")
	if !IsAdRequest(req) {
		t.Fatal("expected fundingchoicesmessages.google.com to be blocked")
	}
}

func TestIsAdRequestBlocksAdPatterns(t *testing.T) {
	patterns := []string{
		"/pagead/",
		"/api/stats/ads",
		"/get_video_info",
		"/youtubei/v1/log_event",
		"/youtubei/v1/player/ad_break",
		"/ddm/",
		"/td/",
		"/adi/",
		"/adj/",
		"/activityi;",
		"/pagead/adview",
		"/pagead/conversion",
		"/pagead/lvz",
		"/pagead/viewthroughconversion",
		"/pcs/activeview",
		"/ima/",
		"/instream/ad/",
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			req := mustRequest(t, "GET", "https://www.youtube.com"+pattern)
			if !IsAdRequest(req) {
				t.Errorf("expected URL pattern %s to be blocked", pattern)
			}
		})
	}
}

func TestIsAdRequestBlocksAdQueryParameters(t *testing.T) {
	queryParams := []string{
		"ad_type=banner",
		"adformat=15_2_1",
		"adunit=123",
		"ad_cpn=abc123",
		"ad_id=xyz",
		"ad_len=15000",
		"ad_mt=video",
		"ad_playback=1",
		"ad_sys=internal",
		"adsense_video_doc_id=12345",
		"is_ad=1",
		"pltype=adhost",
	}

	for _, param := range queryParams {
		t.Run(param, func(t *testing.T) {
			req := mustRequest(t, "GET", "https://www.youtube.com/watch?v=abc&"+param)
			if !IsAdRequest(req) {
				t.Errorf("expected query parameter %s to trigger block", param)
			}
		})
	}
}

func TestIsAdRequestAllowsContentVideoSegment(t *testing.T) {
	req := mustRequest(t, "POST", "https://r4.googlevideo.com/videoplayback?source=youtube&fmt=399")
	if IsAdRequest(req) {
		t.Fatal("expected content video segment to be allowed")
	}
}

func TestIsAdRequestAllowsNormalYouTubeDomains(t *testing.T) {
	requests := []string{
		"https://www.youtube.com/watch?v=abc123",
		"https://www.youtube.com/api/stats/qoe?fmt=399&cpn=abc",
		"https://www.youtube.com/ptracking?video_id=abc&pltype=content",
	}

	for _, url := range requests {
		t.Run(url, func(t *testing.T) {
			req := mustRequest(t, "GET", url)
			if IsAdRequest(req) {
				t.Errorf("expected normal YouTube request to be allowed: %s", url)
			}
		})
	}
}

func TestIsAdRequestGoogleVideoAdSegmentMarkers(t *testing.T) {
	testCases := []struct {
		url     string
		blocked bool
		name    string
	}{
		{"https://r4.googlevideo.com/videoplayback?ctier=L&source=youtube", true, "ctier=L"},
		{"https://r4.googlevideo.com/videoplayback?ctier=A&source=youtube", true, "ctier=A"},
		{"https://r4.googlevideo.com/videoplayback?oad&source=youtube", true, "?oad"},
		{"https://r4.googlevideo.com/videoplayback?source=youtube&oad", true, "&oad"},
		{"https://r4.googlevideo.com/videoplayback?ctier=M&source=youtube", false, "ctier=M (normal)"},
		{"https://r4.googlevideo.com/videoplayback?source=youtube&fmt=399", false, "fmt=399"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := mustRequest(t, "POST", tc.url)
			result := IsAdRequest(req)
			if result != tc.blocked {
				t.Errorf("URL %s: expected %v, got %v", tc.url, tc.blocked, result)
			}
		})
	}
}

func TestIsAdRequestHostWithPort(t *testing.T) {
	req := mustRequest(t, "GET", "https://imasdk.googleapis.com:443/request")
	if !IsAdRequest(req) {
		t.Fatal("expected ad host with port to be blocked")
	}
}

func TestIsAdRequestSubdomainOfAdHost(t *testing.T) {
	// Note: Current implementation does NOT block subdomains of ad hosts
	// It only does exact host matching
	req := mustRequest(t, "GET", "https://sub.imasdk.googleapis.com/request")
	if IsAdRequest(req) {
		t.Fatal("subdomains of ad hosts are not blocked (only exact matches)")
	}
}

func TestIsAdRequestMultipleAdIndicators(t *testing.T) {
	// URL with both pattern and query parameter
	req := mustRequest(t, "GET", "https://www.youtube.com/pagead/path?ad_type=banner")
	if !IsAdRequest(req) {
		t.Fatal("expected URL with multiple ad indicators to be blocked")
	}
}

func TestIsAdRequestCorrelatorParameter(t *testing.T) {
	// correlator is only in ad requests
	req := mustRequest(t, "GET", "https://www.youtube.com/api/stats?correlator=123456")
	if !IsAdRequest(req) {
		t.Fatal("expected request with correlator parameter to be blocked")
	}
}

func TestIsAdRequestRemarketingFlag(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/api/stats?rmktEnabled=1")
	if !IsAdRequest(req) {
		t.Fatal("expected request with rmktEnabled flag to be blocked")
	}
}

func TestIsAdRequestAfvAdTag(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/api/stats?afv_ad_tag=pre_roll")
	if !IsAdRequest(req) {
		t.Fatal("expected request with afv_ad_tag to be blocked")
	}
}

func TestIsAdRequest2mdnHosts(t *testing.T) {
	hosts := []string{
		"s0.2mdn.net",
		"s1.2mdn.net",
		"s2.2mdn.net",
	}

	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			req := mustRequest(t, "GET", "https://"+host+"/ad")
			if !IsAdRequest(req) {
				t.Errorf("expected %s to be blocked", host)
			}
		})
	}
}

func TestIsAdRequestEmptyPath(t *testing.T) {
	req := mustRequest(t, "GET", "https://imasdk.googleapis.com/")
	if !IsAdRequest(req) {
		t.Fatal("expected ad host with empty path to be blocked")
	}
}

func TestIsAdRequestCaseInsensitiveHost(t *testing.T) {
	// Note: Current implementation does NOT do case-insensitive host matching
	// It does exact case-sensitive matching
	req := mustRequest(t, "GET", "https://IMASDK.GOOGLEAPIS.COM/request")
	req.Host = "IMASDK.GOOGLEAPIS.COM"
	if IsAdRequest(req) {
		t.Fatal("host matching is case-sensitive, uppercase does not match")
	}

	// But lowercase should match
	req2 := mustRequest(t, "GET", "https://imasdk.googleapis.com/request")
	if !IsAdRequest(req2) {
		t.Fatal("expected lowercase host to match")
	}
}

func TestIsAdRequestPathCaseSensitive(t *testing.T) {
	// Paths are case-sensitive in the contains check
	req := mustRequest(t, "GET", "https://www.youtube.com/PAGEAD/something")
	if IsAdRequest(req) {
		t.Fatal("uppercase /PAGEAD should NOT match lowercase /pagead pattern")
	}

	// But lowercase should match
	req2 := mustRequest(t, "GET", "https://www.youtube.com/pagead/something")
	if !IsAdRequest(req2) {
		t.Fatal("expected /pagead to be blocked")
	}
}

func TestIsAdRequestEmptyRequest(t *testing.T) {
	req := mustRequest(t, "GET", "https://example.com/")
	if IsAdRequest(req) {
		t.Fatal("expected normal request to be allowed")
	}
}

func TestIsAdRequestQueryStringWithoutValue(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/api?ad_type&other=value")
	if !IsAdRequest(req) {
		t.Fatal("expected query parameter without value to be detected")
	}
}

func TestIsAdRequestInStreamAdSlot(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/instream/ad/something")
	if !IsAdRequest(req) {
		t.Fatal("expected /instream/ad/ to be blocked")
	}
}

func TestIsAdRequestAdSlotParameter(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/api?adslot=123")
	if !IsAdRequest(req) {
		t.Fatal("expected adslot parameter to trigger block")
	}
}
