package handlers

import (
        "testing"
)

func TestRoadmapItemStruct(t *testing.T) {
        item := RoadmapItem{
                Title:    "Test Feature",
                Version:  "v1.0.0",
                Date:     "Feb 2026",
                Notes:    "Some notes",
                Type:     "Feature",
                Priority: "High",
        }
        if item.Title != "Test Feature" {
                t.Errorf("Title = %q, want 'Test Feature'", item.Title)
        }
        if item.Version != "v1.0.0" {
                t.Errorf("Version = %q, want 'v1.0.0'", item.Version)
        }
        if item.Priority != "High" {
                t.Errorf("Priority = %q, want 'High'", item.Priority)
        }
}

func TestNewRoadmapHandler(t *testing.T) {
        h := NewRoadmapHandler(nil)
        if h == nil {
                t.Fatal("expected non-nil handler")
        }
}

func TestRoadmapPageConstants(t *testing.T) {
        if roadmapDateFeb2026 != "Feb 2026" {
                t.Errorf("roadmapDateFeb2026 = %q", roadmapDateFeb2026)
        }
        if roadmapTypeFeature != "Feature" {
                t.Errorf("roadmapTypeFeature = %q", roadmapTypeFeature)
        }
        if priorityLow != "Low" {
                t.Errorf("priorityLow = %q", priorityLow)
        }
        if priorityHigh != "High" {
                t.Errorf("priorityHigh = %q", priorityHigh)
        }
        if strMedium != "Medium" {
                t.Errorf("strMedium = %q", strMedium)
        }
        if strQuality != "Quality" {
                t.Errorf("strQuality = %q", strQuality)
        }
}
