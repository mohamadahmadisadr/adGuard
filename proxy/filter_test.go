package proxy

import (
	"net/http"
	"testing"
)

func TestIsAdRequestBlocksYouTubeAdBreak(t *testing.T) {
	req := mustRequest(t, "POST", "https://www.youtube.com/youtubei/v1/player/ad_break?prettyPrint=false")

	if !IsAdRequest(req) {
		t.Fatal("expected YouTube ad_break request to be blocked")
	}
}

func TestIsAdRequestBlocksAdTaggedYouTubeTelemetry(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/pcs/activeview?ad_cpn=vSSmvVoikcR1bqnu&id=lidarv")

	if !IsAdRequest(req) {
		t.Fatal("expected ad-tagged YouTube activeview request to be blocked")
	}
}

func TestIsAdRequestBlocksGoogleVideoAdSegment(t *testing.T) {
	req := mustRequest(t, "POST", "https://rr4---sn-gvbxgn-tvf6.googlevideo.com/videoplayback?ctier=L&source=youtube")

	if !IsAdRequest(req) {
		t.Fatal("expected googlevideo ad segment to be blocked")
	}
}

func TestIsAdRequestAllowsGoogleVideoContentSegment(t *testing.T) {
	req := mustRequest(t, "POST", "https://rr2---sn-gvbxgn-tvfz.googlevideo.com/videoplayback?source=youtube&fmt=399")

	if IsAdRequest(req) {
		t.Fatal("expected ordinary googlevideo content segment to be allowed")
	}
}

func TestIsAdRequestAllowsGoogleVideoConnectivityProbe(t *testing.T) {
	req := mustRequest(t, "GET", "https://rr1---sn-gvbxgn-tvf6.googlevideo.com/generate_204")

	if IsAdRequest(req) {
		t.Fatal("expected googlevideo connectivity probe to be allowed")
	}
}

func TestIsAdRequestAllowsNormalYouTubeQoE(t *testing.T) {
	req := mustRequest(t, "POST", "https://www.youtube.com/api/stats/qoe?fmt=399&cpn=abc&el=detailpage")

	if IsAdRequest(req) {
		t.Fatal("expected normal YouTube QoE telemetry to be allowed")
	}
}

func TestIsAdRequestBlocksAdTaggedYouTubeQoE(t *testing.T) {
	req := mustRequest(t, "POST", "https://www.youtube.com/api/stats/qoe?fmt=400&cpn=abc&adformat=15_2_1")

	if !IsAdRequest(req) {
		t.Fatal("expected ad-tagged YouTube QoE telemetry to be blocked")
	}
}

func TestIsAdRequestAllowsContentPtracking(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/ptracking?video_id=abc&pltype=content")

	if IsAdRequest(req) {
		t.Fatal("expected content ptracking to be allowed")
	}
}

func TestIsAdRequestBlocksAdHostPtracking(t *testing.T) {
	req := mustRequest(t, "GET", "https://www.youtube.com/ptracking?video_id=abc&pltype=adhost")

	if !IsAdRequest(req) {
		t.Fatal("expected adhost ptracking to be blocked")
	}
}

func mustRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
