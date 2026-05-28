package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestShouldSanitizeYouTubeResponsePlayerAPI(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		path     string
		expected bool
	}{
		{"player endpoint", "www.youtube.com", "/youtubei/v1/player", true},
		{"next endpoint", "www.youtube.com", "/youtubei/v1/next", true},
		{"get_watch endpoint", "www.youtube.com", "/youtubei/v1/get_watch", true},
		{"other endpoint", "www.youtube.com", "/youtubei/v1/other", false},
		{"wrong host player", "m.youtube.com", "/youtubei/v1/player", false},
		{"youtubei.googleapis.com player", "youtubei.googleapis.com", "/youtubei/v1/player", true},
		{"youtubei.googleapis.com next", "youtubei.googleapis.com", "/youtubei/v1/next", true},
		{"unrelated host", "google.com", "/youtubei/v1/player", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host: tt.host,
				URL:  &url.URL{Path: tt.path},
			}
			result := shouldSanitizeYouTubeResponse(req)
			if result != tt.expected {
				t.Errorf("shouldSanitizeYouTubeResponse(%s, %s) = %v, expected %v", tt.host, tt.path, result, tt.expected)
			}
		})
	}
}

func TestDrainRequestBodyWithNilBody(t *testing.T) {
	req := &http.Request{Body: nil}
	err := drainRequestBody(req)
	if err != nil {
		t.Fatalf("drainRequestBody should not error on nil body, got %v", err)
	}
}

func TestDrainRequestBodyWithNoBody(t *testing.T) {
	req := &http.Request{Body: http.NoBody}
	err := drainRequestBody(req)
	if err != nil {
		t.Fatalf("drainRequestBody should not error on http.NoBody, got %v", err)
	}
}

func TestDrainRequestBodyWithData(t *testing.T) {
	bodyData := []byte("test body content")
	req := &http.Request{
		Body: io.NopCloser(bytes.NewReader(bodyData)),
	}
	err := drainRequestBody(req)
	if err != nil {
		t.Fatalf("drainRequestBody should not error on valid body, got %v", err)
	}
}

func TestStripHopHeaders(t *testing.T) {
	header := http.Header{
		"Connection":          []string{"close"},
		"Proxy-Connection":    []string{"keep-alive"},
		"Keep-Alive":          []string{"300"},
		"Proxy-Authenticate":  []string{"Basic"},
		"Proxy-Authorization": []string{"Bearer token"},
		"Te":                  []string{"trailers"},
		"Trailers":            []string{"X-Custom"},
		"Transfer-Encoding":   []string{"chunked"},
		"Upgrade":             []string{"websocket"},
		"Content-Type":        []string{"application/json"},
		"Content-Length":      []string{"42"},
	}

	stripHopHeaders(header)

	hopHeaderNames := []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
	}

	for _, name := range hopHeaderNames {
		if _, ok := header[name]; ok {
			t.Errorf("hop header %s should have been removed", name)
		}
	}

	// Verify non-hop headers are preserved
	if _, ok := header["Content-Type"]; !ok {
		t.Error("Content-Type should not be removed")
	}
	if _, ok := header["Content-Length"]; !ok {
		t.Error("Content-Length should not be removed")
	}
}

func TestStripHopHeadersWithConnectionHeaderValue(t *testing.T) {
	header := http.Header{
		"Connection":      []string{"close, X-Custom-Header"},
		"X-Custom-Header": []string{"value"},
		"Content-Type":    []string{"application/json"},
	}

	stripHopHeaders(header)

	// Connection header is removed
	if _, ok := header["Connection"]; ok {
		t.Error("Connection header should be removed")
	}
	// X-Custom-Header is NOT removed (because Connection is deleted before reading its value)
	if _, ok := header["X-Custom-Header"]; !ok {
		t.Error("X-Custom-Header should not be removed (Connection header value is not parsed)")
	}
	if _, ok := header["Content-Type"]; !ok {
		t.Error("Content-Type should not be removed")
	}
}

func TestStripYouTubeAdFieldsMap(t *testing.T) {
	payload := map[string]interface{}{
		"videoDetails": map[string]interface{}{
			"videoId": "abc123",
		},
		"adPlacements": []interface{}{
			map[string]interface{}{"adPlacementRenderer": "x"},
		},
		"playerAds": []interface{}{
			map[string]interface{}{"playerLegacyDesktopYpcOfferRenderer": "y"},
		},
	}

	changed := stripYouTubeAdFields(payload)
	if !changed {
		t.Fatal("expected stripYouTubeAdFields to report changes")
	}

	// Verify ad fields are removed
	if _, ok := payload["adPlacements"]; ok {
		t.Error("adPlacements should be removed")
	}
	if _, ok := payload["playerAds"]; ok {
		t.Error("playerAds should be removed")
	}

	// Verify non-ad fields are preserved
	if _, ok := payload["videoDetails"]; !ok {
		t.Error("videoDetails should be preserved")
	}
}

func TestStripYouTubeAdFieldsNestedMap(t *testing.T) {
	payload := map[string]interface{}{
		"nested": map[string]interface{}{
			"adSlots": []interface{}{
				map[string]interface{}{"slot": 1},
			},
			"content": "keep",
		},
	}

	changed := stripYouTubeAdFields(payload)
	if !changed {
		t.Fatal("expected stripYouTubeAdFields to report changes for nested fields")
	}

	nested := payload["nested"].(map[string]interface{})
	if _, ok := nested["adSlots"]; ok {
		t.Error("nested adSlots should be removed")
	}
	if content, ok := nested["content"]; !ok || content != "keep" {
		t.Error("nested content should be preserved")
	}
}

func TestStripYouTubeAdFieldsNoChanges(t *testing.T) {
	payload := map[string]interface{}{
		"videoDetails": map[string]interface{}{
			"videoId": "abc123",
		},
		"streamingData": map[string]interface{}{
			"formats": []interface{}{},
		},
	}

	changed := stripYouTubeAdFields(payload)
	if changed {
		t.Fatal("expected stripYouTubeAdFields to report no changes for clean payload")
	}
}

func TestStripYouTubeAdFieldsArray(t *testing.T) {
	payload := []interface{}{
		map[string]interface{}{
			"adbreakheartbeatparams": "x",
			"content":                "y",
		},
		map[string]interface{}{
			"videoDetails": "z",
		},
	}

	changed := stripYouTubeAdFields(payload)
	if !changed {
		t.Fatal("expected stripYouTubeAdFields to report changes in array")
	}

	first := payload[0].(map[string]interface{})
	if _, ok := first["adbreakheartbeatparams"]; ok {
		t.Error("adbreakheartbeatparams should be removed from array element")
	}
	if content, ok := first["content"]; !ok || content != "y" {
		t.Error("other fields in array element should be preserved")
	}
}

func TestSanitizeYouTubeJSONValid(t *testing.T) {
	body := []byte(`{
		"videoDetails": {"videoId": "abc123"},
		"adPlacements": [{"adPlacementRenderer": "x"}]
	}`)

	sanitized, changed, err := sanitizeYouTubeJSON(body)
	if err != nil {
		t.Fatalf("sanitizeYouTubeJSON should not error: %v", err)
	}
	if !changed {
		t.Fatal("expected sanitizeYouTubeJSON to report changes")
	}

	// Verify sanitized contains ad field removal
	if bytes.Contains(sanitized, []byte("adPlacements")) {
		t.Error("adPlacements should be removed from sanitized JSON")
	}
	if !bytes.Contains(sanitized, []byte("videoDetails")) {
		t.Error("videoDetails should be preserved in sanitized JSON")
	}
}

func TestSanitizeYouTubeJSONInvalid(t *testing.T) {
	body := []byte(`{invalid json}`)

	_, _, err := sanitizeYouTubeJSON(body)
	if err == nil {
		t.Fatal("sanitizeYouTubeJSON should error on invalid JSON")
	}
}

func TestSanitizeYouTubeJSONClean(t *testing.T) {
	body := []byte(`{
		"videoDetails": {"videoId": "abc123"},
		"streamingData": {"formats": []}
	}`)

	sanitized, changed, err := sanitizeYouTubeJSON(body)
	if err != nil {
		t.Fatalf("sanitizeYouTubeJSON should not error: %v", err)
	}
	if changed {
		t.Fatal("expected sanitizeYouTubeJSON to report no changes for clean payload")
	}
	if !bytes.Equal(sanitized, body) {
		t.Error("clean payload should be returned unchanged")
	}
}

func TestSanitizeYouTubeJSONCaseInsensitive(t *testing.T) {
	body := []byte(`{
		"ADPLACEMENTS": [{"adPlacementRenderer": "x"}],
		"AdBreakHeartbeatParams": "y"
	}`)

	sanitized, changed, err := sanitizeYouTubeJSON(body)
	if err != nil {
		t.Fatalf("sanitizeYouTubeJSON should not error: %v", err)
	}
	if !changed {
		t.Fatal("expected sanitizeYouTubeJSON to handle case-insensitive field matching")
	}

	if bytes.Contains(sanitized, []byte("ADPLACEMENTS")) {
		t.Error("case-insensitive ADPLACEMENTS should be removed")
	}
	if bytes.Contains(sanitized, []byte("AdBreakHeartbeatParams")) {
		t.Error("case-insensitive AdBreakHeartbeatParams should be removed")
	}
}
