package analyzer

import (
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name          string
		dsRecords     []string
		wantAlgo      *int
		wantAlgoName  string
		wantNilAlgo   bool
		wantNilName   bool
	}{
		{
			"empty records",
			[]string{},
			nil, "", true, true,
		},
		{
			"RSA/SHA-256 algo 8",
			[]string{"12345 8 2 AABBCCDD"},
			intPtr(8), "RSA/SHA-256", false, false,
		},
		{
			"ECDSA P-256 algo 13",
			[]string{"12345 13 2 AABBCCDD"},
			intPtr(13), "ECDSA P-256/SHA-256", false, false,
		},
		{
			"Ed25519 algo 15",
			[]string{"12345 15 2 AABBCCDD"},
			intPtr(15), "Ed25519", false, false,
		},
		{
			"unknown algo 99",
			[]string{"12345 99 2 AABBCCDD"},
			intPtr(99), "Algorithm 99", false, false,
		},
		{
			"too few fields",
			[]string{"12345"},
			nil, "", true, true,
		},
		{
			"non-numeric algo",
			[]string{"12345 abc 2 AABBCCDD"},
			nil, "", true, true,
		},
		{
			"multiple records uses first",
			[]string{"12345 8 2 AABBCCDD", "67890 13 2 EEFF"},
			intPtr(8), "RSA/SHA-256", false, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, name := parseAlgorithm(tt.dsRecords)
			if tt.wantNilAlgo {
				if algo != nil {
					t.Errorf("expected nil algorithm, got %d", *algo)
				}
			} else {
				if algo == nil {
					t.Fatal("expected non-nil algorithm")
				}
				if *algo != *tt.wantAlgo {
					t.Errorf("algorithm = %d, want %d", *algo, *tt.wantAlgo)
				}
			}
			if tt.wantNilName {
				if name != nil {
					t.Errorf("expected nil name, got %q", *name)
				}
			} else {
				if name == nil {
					t.Fatal("expected non-nil name")
				}
				if *name != tt.wantAlgoName {
					t.Errorf("name = %q, want %q", *name, tt.wantAlgoName)
				}
			}
		})
	}
}

func TestAlgorithmObservation(t *testing.T) {
	t.Run("nil algorithm", func(t *testing.T) {
		got := algorithmObservation(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("known algorithm 13", func(t *testing.T) {
		algo := 13
		got := algorithmObservation(&algo)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got["strength"] != "modern" {
			t.Errorf("strength = %v, want modern", got["strength"])
		}
		if got["label"] != "Modern" {
			t.Errorf("label = %v, want Modern", got["label"])
		}
		if got["rfc"] == nil || got["rfc"] == "" {
			t.Error("rfc should not be empty")
		}
		if got["observation"] == nil || got["observation"] == "" {
			t.Error("observation should not be empty")
		}
		if got["quantum_note"] == nil || got["quantum_note"] == "" {
			t.Error("quantum_note should not be empty")
		}
	})

	t.Run("deprecated algorithm 1", func(t *testing.T) {
		algo := 1
		got := algorithmObservation(&algo)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got["strength"] != "deprecated" {
			t.Errorf("strength = %v, want deprecated", got["strength"])
		}
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		algo := 999
		got := algorithmObservation(&algo)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got["strength"] != "adequate" {
			t.Errorf("strength = %v, want adequate", got["strength"])
		}
	})
}

func TestCollectDNSKEYRecords(t *testing.T) {
	tests := []struct {
		name       string
		results    []string
		wantHas    bool
		wantCount  int
	}{
		{"empty", []string{}, false, 0},
		{"single short record", []string{"256 3 13 KEY"}, true, 1},
		{"three records", []string{"rec1", "rec2", "rec3"}, true, 3},
		{
			"more than three records truncated",
			[]string{"rec1", "rec2", "rec3", "rec4", "rec5"},
			true, 3,
		},
		{
			"long record truncated at 100",
			[]string{
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			true, 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, records := collectDNSKEYRecords(tt.results)
			if has != tt.wantHas {
				t.Errorf("has = %v, want %v", has, tt.wantHas)
			}
			if len(records) != tt.wantCount {
				t.Errorf("count = %d, want %d", len(records), tt.wantCount)
			}
		})
	}

	t.Run("long record ends with ellipsis", func(t *testing.T) {
		longRec := make([]byte, 150)
		for i := range longRec {
			longRec[i] = 'A'
		}
		_, records := collectDNSKEYRecords([]string{string(longRec)})
		if len(records) != 1 {
			t.Fatal("expected 1 record")
		}
		if len(records[0]) != 103 {
			t.Errorf("truncated record length = %d, want 103", len(records[0]))
		}
	})
}

func TestCollectDSRecords(t *testing.T) {
	tests := []struct {
		name      string
		results   []string
		wantHas   bool
		wantCount int
	}{
		{"empty", []string{}, false, 0},
		{"single record", []string{"12345 8 2 AABB"}, true, 1},
		{"three records", []string{"r1", "r2", "r3"}, true, 3},
		{"more than three", []string{"r1", "r2", "r3", "r4"}, true, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, records := collectDSRecords(tt.results)
			if has != tt.wantHas {
				t.Errorf("has = %v, want %v", has, tt.wantHas)
			}
			if len(records) != tt.wantCount {
				t.Errorf("count = %d, want %d", len(records), tt.wantCount)
			}
		})
	}
}

func TestBuildDNSSECResult(t *testing.T) {
	algo8 := 8
	algoName := "RSA/SHA-256"
	resolver := "8.8.8.8"

	t.Run("full DNSSEC with AD flag", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         true,
			adFlag:        true,
			dnskeyRecords: []string{"key1"},
			dsRecords:     []string{"ds1"},
			algorithm:     &algo8,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "complete" {
			t.Errorf("chain_of_trust = %v, want complete", r[mapKeyChainOfTrust])
		}
		if r[mapKeyAdFlag] != true {
			t.Errorf("ad_flag = %v, want true", r[mapKeyAdFlag])
		}
		if r[mapKeyHasDnskey] != true {
			t.Error("has_dnskey should be true")
		}
		if r[mapKeyHasDs] != true {
			t.Error("has_ds should be true")
		}
	})

	t.Run("full DNSSEC without AD flag", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         true,
			adFlag:        false,
			dnskeyRecords: []string{"key1"},
			dsRecords:     []string{"ds1"},
			algorithm:     &algo8,
			algorithmName: &algoName,
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyAdFlag] != false {
			t.Errorf("ad_flag = %v, want false", r[mapKeyAdFlag])
		}
	})

	t.Run("DNSKEY only no DS", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:     true,
			hasDS:         false,
			dnskeyRecords: []string{"key1"},
			adResolver:    &resolver,
		})
		if r[mapKeyStatus] != "warning" {
			t.Errorf("status = %v, want warning", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "broken" {
			t.Errorf("chain_of_trust = %v, want broken", r[mapKeyChainOfTrust])
		}
	})

	t.Run("no DNSSEC", func(t *testing.T) {
		r := buildDNSSECResult(dnssecParams{
			hasDNSKEY:  false,
			hasDS:      false,
			adResolver: &resolver,
		})
		if r[mapKeyStatus] != "warning" {
			t.Errorf("status = %v, want warning", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "none" {
			t.Errorf("chain_of_trust = %v, want none", r[mapKeyChainOfTrust])
		}
		if r[mapKeyHasDnskey] != false {
			t.Error("has_dnskey should be false")
		}
		if r[mapKeyHasDs] != false {
			t.Error("has_ds should be false")
		}
	})
}

func TestBuildInheritedDNSSECResult(t *testing.T) {
	resolver := "8.8.8.8"
	algo := 13
	algoName := "ECDSA P-256/SHA-256"

	t.Run("with parent zone", func(t *testing.T) {
		r := buildInheritedDNSSECResult("example.com", &resolver, &algo, &algoName)
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		if r[mapKeyChainOfTrust] != "inherited" {
			t.Errorf("chain_of_trust = %v, want inherited", r[mapKeyChainOfTrust])
		}
		if r[mapKeyAdFlag] != true {
			t.Errorf("ad_flag = %v, want true", r[mapKeyAdFlag])
		}
		if r["is_subdomain"] != true {
			t.Error("is_subdomain should be true")
		}
		if r["parent_zone"] != "example.com" {
			t.Errorf("parent_zone = %v, want example.com", r["parent_zone"])
		}
	})

	t.Run("without parent zone", func(t *testing.T) {
		r := buildInheritedDNSSECResult("", &resolver, nil, nil)
		if r[mapKeyStatus] != "success" {
			t.Errorf("status = %v, want success", r[mapKeyStatus])
		}
		msg, _ := r[mapKeyMessage].(string)
		if msg == "" {
			t.Error("message should not be empty")
		}
	})
}

func intPtr(n int) *int {
	return &n
}
