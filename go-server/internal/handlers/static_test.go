package handlers

import (
	"testing"
)

func TestNewStaticHandler(t *testing.T) {
	h := NewStaticHandler("/static", "1.0.0", "https://example.com")
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.StaticDir != "/static" {
		t.Errorf("StaticDir = %q, want /static", h.StaticDir)
	}
	if h.AppVersion != "1.0.0" {
		t.Errorf("AppVersion = %q, want 1.0.0", h.AppVersion)
	}
	if h.BaseURL != "https://example.com" {
		t.Errorf("BaseURL = %q, want https://example.com", h.BaseURL)
	}
}

func TestStaticHandlerConstants(t *testing.T) {
	if headerContentType != "Content-Type" {
		t.Errorf("headerContentType = %q", headerContentType)
	}
	if headerCacheControl != "Cache-Control" {
		t.Errorf("headerCacheControl = %q", headerCacheControl)
	}
	if cachePublicDay != "public, max-age=86400" {
		t.Errorf("cachePublicDay = %q", cachePublicDay)
	}
}

func TestSitemapPriorityConstants(t *testing.T) {
	if sitemapPriorityHigh != "0.7" {
		t.Errorf("sitemapPriorityHigh = %q", sitemapPriorityHigh)
	}
	if sitemapPriorityMedium != "0.6" {
		t.Errorf("sitemapPriorityMedium = %q", sitemapPriorityMedium)
	}
	if sitemapPriorityLow != "0.5" {
		t.Errorf("sitemapPriorityLow = %q", sitemapPriorityLow)
	}
}
