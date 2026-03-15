package handlers

import (
	"testing"
)

func TestTopN(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		result := topN(nil, 5)
		if len(result) != 0 {
			t.Errorf("expected 0, got %d", len(result))
		}
	})

	t.Run("fewer than n", func(t *testing.T) {
		m := map[string]int{"google": 10, "bing": 5}
		result := topN(m, 5)
		if len(result) != 2 {
			t.Fatalf("expected 2, got %d", len(result))
		}
		if result[0].Source != "google" || result[0].Count != 10 {
			t.Errorf("first entry = %+v, want google/10", result[0])
		}
		if result[1].Source != "bing" || result[1].Count != 5 {
			t.Errorf("second entry = %+v, want bing/5", result[1])
		}
	})

	t.Run("more than n truncates", func(t *testing.T) {
		m := map[string]int{
			"a": 100, "b": 90, "c": 80, "d": 70, "e": 60,
			"f": 50, "g": 40, "h": 30, "i": 20, "j": 10, "k": 5,
		}
		result := topN(m, 3)
		if len(result) != 3 {
			t.Fatalf("expected 3, got %d", len(result))
		}
		if result[0].Count != 100 {
			t.Errorf("first count = %d, want 100", result[0].Count)
		}
		if result[1].Count != 90 {
			t.Errorf("second count = %d, want 90", result[1].Count)
		}
		if result[2].Count != 80 {
			t.Errorf("third count = %d, want 80", result[2].Count)
		}
	})

	t.Run("sorted descending", func(t *testing.T) {
		m := map[string]int{"z": 1, "y": 50, "x": 25}
		result := topN(m, 10)
		for i := 1; i < len(result); i++ {
			if result[i].Count > result[i-1].Count {
				t.Errorf("not sorted: %d > %d at index %d", result[i].Count, result[i-1].Count, i)
			}
		}
	})
}

func TestTopNPages(t *testing.T) {
	t.Run("empty map", func(t *testing.T) {
		result := topNPages(nil, 5)
		if len(result) != 0 {
			t.Errorf("expected 0, got %d", len(result))
		}
	})

	t.Run("fewer than n", func(t *testing.T) {
		m := map[string]int{"/home": 100, "/about": 50}
		result := topNPages(m, 5)
		if len(result) != 2 {
			t.Fatalf("expected 2, got %d", len(result))
		}
		if result[0].Path != "/home" || result[0].Count != 100 {
			t.Errorf("first = %+v, want /home/100", result[0])
		}
	})

	t.Run("more than n truncates", func(t *testing.T) {
		m := map[string]int{
			"/a": 10, "/b": 20, "/c": 30, "/d": 40, "/e": 50,
		}
		result := topNPages(m, 3)
		if len(result) != 3 {
			t.Fatalf("expected 3, got %d", len(result))
		}
		if result[0].Count != 50 {
			t.Errorf("top count = %d, want 50", result[0].Count)
		}
	})

	t.Run("sorted descending", func(t *testing.T) {
		m := map[string]int{"/x": 5, "/y": 500, "/z": 50}
		result := topNPages(m, 10)
		for i := 1; i < len(result); i++ {
			if result[i].Count > result[i-1].Count {
				t.Errorf("not sorted: %d > %d at index %d", result[i].Count, result[i-1].Count, i)
			}
		}
	})
}

func TestNewAnalyticsHandler(t *testing.T) {
	h := NewAnalyticsHandler(nil, nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.DB != nil {
		t.Error("expected nil DB")
	}
}

func TestAnalyticsDayStruct(t *testing.T) {
	d := AnalyticsDay{
		Date:                  "2024-01-15",
		Pageviews:             100,
		UniqueVisitors:        50,
		AnalysesRun:           25,
		UniqueDomainsAnalyzed: 20,
		ReferrerSources:       map[string]int{"google": 10},
		TopPages:              map[string]int{"/": 50},
	}
	if d.Date != "2024-01-15" {
		t.Errorf("Date = %q", d.Date)
	}
	if d.Pageviews != 100 {
		t.Errorf("Pageviews = %d", d.Pageviews)
	}
}

func TestAnalyticsSummaryStruct(t *testing.T) {
	s := AnalyticsSummary{
		TotalPageviews:      1000,
		TotalUniqueVisitors: 500,
		TotalAnalyses:       200,
		TotalUniqueDomains:  150,
		DaysTracked:         30,
		AvgDailyPageviews:   33,
		AvgDailyVisitors:    16,
		TopReferrers:        []ReferrerEntry{{Source: "google", Count: 100}},
		TopPages:            []PageEntry{{Path: "/", Count: 500}},
	}
	if s.TotalPageviews != 1000 {
		t.Errorf("TotalPageviews = %d", s.TotalPageviews)
	}
	if len(s.TopReferrers) != 1 {
		t.Errorf("TopReferrers len = %d", len(s.TopReferrers))
	}
}
