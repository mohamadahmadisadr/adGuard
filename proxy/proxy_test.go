package proxy

import (
	"strings"
	"testing"
)

func TestSanitizeYouTubeJSONRemovesNestedAdFields(t *testing.T) {
	body := []byte(`{
		"playabilityStatus": {"status": "OK"},
		"videoDetails": {"videoId": "abc123"},
		"adPlacements": [{"adPlacementRenderer": {"config": "x"}}],
		"playerAds": [{"playerLegacyDesktopYpcOfferRenderer": {}}],
		"nested": {
			"adSlots": [{"slot": 1}],
			"keep": "value"
		}
	}`)

	sanitized, changed, err := sanitizeYouTubeJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected sanitizer to report a change")
	}

	output := string(sanitized)
	for _, forbidden := range []string{"adPlacements", "playerAds", "adSlots", "playerLegacyDesktopYpcOfferRenderer"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("expected %q to be removed from %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "videoDetails") || !strings.Contains(output, "keep") {
		t.Fatalf("expected non-ad fields to be preserved in %s", output)
	}
}

func TestSanitizeYouTubeJSONKeepsNonAdPayload(t *testing.T) {
	body := []byte(`{"videoDetails":{"videoId":"abc123"},"streamingData":{"formats":[]}}`)

	sanitized, changed, err := sanitizeYouTubeJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected clean payload to be unchanged")
	}
	if string(sanitized) != string(body) {
		t.Fatalf("expected original body, got %s", sanitized)
	}
}
