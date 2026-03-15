package citation

import (
        "strings"
        "testing"
)

func TestRegistryLoads(t *testing.T) {
        r := Global()
        all := r.All()
        if len(all) == 0 {
                t.Fatal("expected non-empty registry")
        }
}

func TestLookupByID(t *testing.T) {
        r := Global()
        tests := []struct {
                id    string
                found bool
                title string
        }{
                {"rfc:7208", true, "Sender Policy Framework"},
                {"rfc:7489", true, "DMARC"},
                {"rfc:6376", true, "DKIM"},
                {"nist:800-177", true, "Trustworthy Email"},
                {"odni:icd-203", true, "Analytic Standards"},
                {"iso:25012", true, "Data Quality"},
                {"nonexistent:123", false, ""},
        }
        for _, tt := range tests {
                e, ok := r.Lookup(tt.id)
                if ok != tt.found {
                        t.Errorf("Lookup(%q): got found=%v, want %v", tt.id, ok, tt.found)
                        continue
                }
                if ok && !strings.Contains(e.Title, tt.title) {
                        t.Errorf("Lookup(%q): title=%q, want it to contain %q", tt.id, e.Title, tt.title)
                }
        }
}

func TestLookupWithSection(t *testing.T) {
        r := Global()
        e, ok := r.Lookup("rfc:7489§6.3")
        if !ok {
                t.Fatal("expected to find rfc:7489 when looking up rfc:7489§6.3")
        }
        if e.ID != "rfc:7489" {
                t.Errorf("expected ID rfc:7489, got %s", e.ID)
        }
}

func TestResolveRFC(t *testing.T) {
        r := Global()
        label, url := r.ResolveRFC("rfc:7489§6.3")
        if label != "RFC 7489 §6.3" {
                t.Errorf("label=%q, want RFC 7489 §6.3", label)
        }
        if !strings.Contains(url, "section-6.3") {
                t.Errorf("url=%q, want section-6.3", url)
        }

        label2, url2 := r.ResolveRFC("rfc:7208")
        if label2 != "RFC 7208" {
                t.Errorf("label=%q, want RFC 7208", label2)
        }
        if url2 != "https://datatracker.ietf.org/doc/html/rfc7208" {
                t.Errorf("url=%q", url2)
        }
}

func TestIsObsolete(t *testing.T) {
        r := Global()
        if !r.IsObsolete("rfc:8624") {
                t.Error("expected rfc:8624 to be obsolete")
        }
        if r.IsObsolete("rfc:7208") {
                t.Error("expected rfc:7208 to not be obsolete")
        }
}

func TestFilter(t *testing.T) {
        r := Global()
        rfcs := r.ByType("rfc")
        if len(rfcs) == 0 {
                t.Fatal("expected non-empty RFC list")
        }
        for _, e := range rfcs {
                if e.Type != "rfc" {
                        t.Errorf("ByType(rfc): got type=%q for %s", e.Type, e.ID)
                }
        }

        email := r.ByFunctionalArea("email-authentication")
        if len(email) == 0 {
                t.Fatal("expected non-empty email-authentication list")
        }

        filtered := r.Filter("rfc", "standards-track", "email-authentication", "")
        if len(filtered) == 0 {
                t.Fatal("expected non-empty filtered list")
        }
}

func TestSearch(t *testing.T) {
        r := Global()
        results := r.Search("DMARC")
        if len(results) == 0 {
                t.Fatal("expected search for DMARC to return results")
        }
}

func TestManifest(t *testing.T) {
        m := NewManifest()
        m.Cite("rfc:7208")
        m.Cite("rfc:7489")
        m.Cite("rfc:7208")

        ids := m.IDs()
        if len(ids) != 2 {
                t.Errorf("expected 2 unique IDs, got %d", len(ids))
        }

        r := Global()
        entries := m.Entries(r)
        if len(entries) != 2 {
                t.Errorf("expected 2 manifest entries, got %d", len(entries))
        }
}

func TestBibTeXExport(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Title: "SPF", URL: "https://example.com", Type: "rfc"},
        }
        out := EntriesToBibTeX(entries)
        if !strings.Contains(out, "@misc{rfc_7208") {
                t.Errorf("BibTeX output missing key: %s", out)
        }
        if !strings.Contains(out, "SPF") {
                t.Errorf("BibTeX output missing title: %s", out)
        }
}

func TestRISExport(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Title: "SPF", URL: "https://example.com", Type: "rfc"},
        }
        out := EntriesToRIS(entries)
        if !strings.Contains(out, "TY  - ELEC") {
                t.Errorf("RIS output missing type: %s", out)
        }
}

func TestCSLJSONExport(t *testing.T) {
        entries := []ManifestEntry{
                {ID: "rfc:7208", Title: "SPF", URL: "https://example.com", Type: "rfc"},
        }
        out, err := EntriesToCSLJSON(entries)
        if err != nil {
                t.Fatalf("CSL-JSON export error: %v", err)
        }
        if !strings.Contains(out, `"id"`) {
                t.Errorf("CSL-JSON output missing id: %s", out)
        }
}

func TestSoftwareExport(t *testing.T) {
        bib := SoftwareToBibTeX("DNS Tool", "1.0", "10.5281/z", "https://x.com", "Doe", "John", "2026-01-01")
        if !strings.Contains(bib, "@software{dnstool") {
                t.Errorf("software BibTeX missing key: %s", bib)
        }
        ris := SoftwareToRIS("DNS Tool", "1.0", "10.5281/z", "https://x.com", "Doe", "John", "2026-01-01")
        if !strings.Contains(ris, "TY  - COMP") {
                t.Errorf("software RIS missing type: %s", ris)
        }
        csl, err := SoftwareToCSLJSON("DNS Tool", "1.0", "10.5281/z", "https://x.com", "Doe", "John", "2026-01-01")
        if err != nil {
                t.Fatalf("software CSL-JSON error: %v", err)
        }
        if !strings.Contains(csl, `"software"`) {
                t.Errorf("software CSL-JSON missing type: %s", csl)
        }
}

func TestDuplicateIDDetection(t *testing.T) {
        yamlData := []byte(`citations:
  - id: "rfc:1234"
    type: rfc
    title: "First"
    url: "https://example.com/1"
    status: current
    area: dns
  - id: "rfc:1234"
    type: rfc
    title: "Duplicate"
    url: "https://example.com/2"
    status: current
    area: dns
`)
        _, err := parseRegistry(yamlData)
        if err == nil {
                t.Fatal("expected error for duplicate ID, got nil")
        }
        if !strings.Contains(err.Error(), "duplicate citation ID") {
                t.Errorf("expected 'duplicate citation ID' error, got: %v", err)
        }
}

func TestEmptyIDDetection(t *testing.T) {
        yamlData := []byte(`citations:
  - id: ""
    type: rfc
    title: "No ID"
    url: "https://example.com"
    status: current
    area: dns
`)
        _, err := parseRegistry(yamlData)
        if err == nil {
                t.Fatal("expected error for empty ID, got nil")
        }
        if !strings.Contains(err.Error(), "empty ID") {
                t.Errorf("expected 'empty ID' error, got: %v", err)
        }
}

func TestNoDuplicateIDsInProductionRegistry(t *testing.T) {
        r := Global()
        all := r.All()
        seen := make(map[string]bool, len(all))
        for _, e := range all {
                if seen[e.ID] {
                        t.Fatalf("production registry has duplicate ID: %s", e.ID)
                }
                seen[e.ID] = true
        }
}

func TestAuthoritiesMDSyncWithRegistry(t *testing.T) {
        for _, path := range []string{
                "../../../AUTHORITIES.md",
                "../../AUTHORITIES.md",
                "../AUTHORITIES.md",
                "AUTHORITIES.md",
        } {
                result, err := ValidateAuthoritiesMD(path)
                if err != nil {
                        continue
                }
                if !result.OK {
                        for _, msg := range result.Messages {
                                t.Error(msg)
                        }
                }
                return
        }
        t.Skip("AUTHORITIES.md not found in expected locations")
}

func TestManifestSectionPreservation(t *testing.T) {
        m := NewManifest()
        m.Cite("rfc:7489§6.3")
        m.Cite("rfc:7208")

        reg := Global()
        entries := m.Entries(reg)

        if len(entries) != 2 {
                t.Fatalf("expected 2 entries, got %d", len(entries))
        }

        var sectionEntry *ManifestEntry
        for i := range entries {
                if entries[i].Section != "" {
                        sectionEntry = &entries[i]
                }
        }
        if sectionEntry == nil {
                t.Fatal("expected one entry with section, got none")
        }
        if sectionEntry.ID != "rfc:7489" {
                t.Errorf("expected base ID rfc:7489, got %s", sectionEntry.ID)
        }
        if sectionEntry.Section != "6.3" {
                t.Errorf("expected section 6.3, got %s", sectionEntry.Section)
        }
        if !strings.Contains(sectionEntry.URL, "#section-6.3") {
                t.Errorf("expected URL with section anchor, got %s", sectionEntry.URL)
        }
}
