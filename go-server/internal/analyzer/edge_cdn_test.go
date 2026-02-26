package analyzer

import (
	"testing"
)

func TestDetectEdgeCDN(t *testing.T) {
	result := DetectEdgeCDN(map[string]any{})
	if result["status"] != "success" {
		t.Errorf("status = %v, want success", result["status"])
	}
	if result["is_behind_cdn"] != false {
		t.Error("expected is_behind_cdn=false for OSS stub")
	}
	if result["origin_visible"] != true {
		t.Error("expected origin_visible=true for OSS stub")
	}
}

func TestCheckASNForCDN(t *testing.T) {
	provider, indicators := checkASNForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestCheckCNAMEForCDN(t *testing.T) {
	provider, indicators := checkCNAMEForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestCheckPTRForCDN(t *testing.T) {
	provider, indicators := checkPTRForCDN(map[string]any{}, nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestMatchASNEntries(t *testing.T) {
	provider, indicators := matchASNEntries(map[string]any{}, "asn", nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if len(indicators) != 0 {
		t.Errorf("indicators = %v, want empty", indicators)
	}
}

func TestClassifyCloudIP(t *testing.T) {
	provider, isCDN := classifyCloudIP("AS13335", nil)
	if provider != "" {
		t.Errorf("provider = %q, want empty", provider)
	}
	if isCDN {
		t.Error("expected isCDN=false for OSS stub")
	}
}

func TestIsOriginVisible(t *testing.T) {
	if isOriginVisible("cloudflare") {
		t.Error("expected false for OSS stub")
	}
}

func TestEdgeCDNMapsEmpty(t *testing.T) {
	if len(cdnASNs) != 0 {
		t.Error("expected cdnASNs to be empty in OSS build")
	}
	if len(cloudASNs) != 0 {
		t.Error("expected cloudASNs to be empty in OSS build")
	}
	if len(cloudCDNPTRPatterns) != 0 {
		t.Error("expected cloudCDNPTRPatterns to be empty in OSS build")
	}
	if len(cdnCNAMEPatterns) != 0 {
		t.Error("expected cdnCNAMEPatterns to be empty in OSS build")
	}
}
