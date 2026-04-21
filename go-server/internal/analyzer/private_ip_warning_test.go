package analyzer

import (
	"reflect"
	"sort"
	"testing"
)

func TestIsCGNATIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"100.64.0.1", true},
		{"100.100.50.1", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
		{"::1", false},
		{"not-an-ip", false},
	}
	for _, tc := range cases {
		if got := isCGNATIP(tc.ip); got != tc.want {
			t.Errorf("isCGNATIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsCloudMetadataIP(t *testing.T) {
	if !isCloudMetadataIP("169.254.169.254") {
		t.Error("AWS/GCP/Azure IMDS v4 not detected")
	}
	if !isCloudMetadataIP("fd00:ec2::254") {
		t.Error("AWS IMDS v6 not detected")
	}
	if isCloudMetadataIP("8.8.8.8") {
		t.Error("public IP misclassified as metadata")
	}
}

func TestAnnotatePrivateIPWarning_CoversAllRequiredRanges(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"RFC1918-10/8", "10.0.0.1"},
		{"RFC1918-172.16/12", "172.20.5.5"},
		{"RFC1918-192.168/16", "192.168.1.1"},
		{"loopback-127/8", "127.0.0.1"},
		{"link-local-169.254/16", "169.254.10.10"},
		{"ULA-fc00::/7", "fc00::1"},
		{"link-local-v6-fe80::/10", "fe80::1"},
		{"CGNAT-100.64/10", "100.64.1.1"},
		{"cloud-metadata-v4", "169.254.169.254"},
		{"cloud-metadata-v6", "fd00:ec2::254"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			results := map[string]any{
				"basic_records": map[string]any{
					"A":    []string{tc.ip},
					"AAAA": []string{},
				},
			}
			annotatePrivateIPWarning(results)
			warn, ok := results["private_ip_warning"].(map[string]any)
			if !ok {
				t.Fatalf("no private_ip_warning emitted for %s", tc.ip)
			}
			ips, _ := warn["ips"].([]string)
			if len(ips) != 1 || ips[0] != tc.ip {
				t.Errorf("expected ips=[%s], got %v", tc.ip, ips)
			}
		})
	}
}

func TestAnnotatePrivateIPWarning_PublicIPNoWarning(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"A":    []string{"8.8.8.8", "1.1.1.1"},
			"AAAA": []string{"2001:4860:4860::8888"},
		},
	}
	annotatePrivateIPWarning(results)
	if _, ok := results["private_ip_warning"]; ok {
		t.Error("public-only resolution must not trigger warning")
	}
}

func TestAnnotatePrivateIPWarning_MixedFlagsAll(t *testing.T) {
	results := map[string]any{
		"basic_records": map[string]any{
			"A":    []string{"8.8.8.8", "10.0.0.1", "100.64.5.5"},
			"AAAA": []string{"2001:4860:4860::8888", "fc00::1"},
		},
	}
	annotatePrivateIPWarning(results)
	warn, ok := results["private_ip_warning"].(map[string]any)
	if !ok {
		t.Fatal("expected warning")
	}
	ips, _ := warn["ips"].([]string)
	sort.Strings(ips)
	want := []string{"10.0.0.1", "100.64.5.5", "fc00::1"}
	sort.Strings(want)
	if !reflect.DeepEqual(ips, want) {
		t.Errorf("private IP set mismatch: got=%v want=%v", ips, want)
	}
}

func TestCollectAllResolvedIPs_NoCap_DedupAndAnyShape(t *testing.T) {
	many := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		many = append(many, "10.0.0.1") // duplicate to exercise dedup downstream
	}
	results := map[string]any{
		"basic_records": map[string]any{
			"A":    many,
			"AAAA": []any{"fc00::1", "fc00::1"},
		},
	}
	got := collectAllResolvedIPs(results)
	if len(got) != 27 {
		t.Errorf("collectAllResolvedIPs must not cap; got %d, want 27 (pre-dedup)", len(got))
	}
	annotatePrivateIPWarning(results)
	warn := results["private_ip_warning"].(map[string]any)
	ips := warn["ips"].([]string)
	if len(ips) != 2 {
		t.Errorf("expected 2 deduped IPs in warning; got %d (%v)", len(ips), ips)
	}
}
