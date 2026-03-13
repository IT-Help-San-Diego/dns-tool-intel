// dns-tool:scrutiny design
package handlers

import (
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "os"
        "regexp"
        "strconv"
        "strings"

        "dnstool/go-server/internal/citation"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/goccy/go-yaml"
)

var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

type citationCFF struct {
        Title        string      `yaml:"title"`
        Version      string      `yaml:"version"`
        DateReleased string      `yaml:"date-released"`
        DOI          string      `yaml:"doi"`
        URL          string      `yaml:"url"`
        Authors      []cffAuthor `yaml:"authors"`
}

type cffAuthor struct {
        FamilyNames string `yaml:"family-names"`
        GivenNames  string `yaml:"given-names"`
}

func loadCitationCFF() *citationCFF {
        for _, path := range []string{"CITATION.cff", "../CITATION.cff", "../../CITATION.cff"} {
                data, err := os.ReadFile(path)
                if err != nil {
                        continue
                }
                var cff citationCFF
                if err := yaml.Unmarshal(data, &cff); err != nil {
                        slog.Warn("Failed to parse CITATION.cff", "path", path, "error", err)
                        return nil
                }
                return &cff
        }
        return nil
}

type CitationHandler struct {
        Config   *config.Config
        Registry *citation.Registry
        DB       *db.Database
}

func NewCitationHandler(cfg *config.Config, reg *citation.Registry, database *db.Database) *CitationHandler {
        return &CitationHandler{Config: cfg, Registry: reg, DB: database}
}

func (h *CitationHandler) Authorities(c *gin.Context) {
        typ := c.Query("type")
        status := c.Query("status")
        area := c.Query("area")
        query := c.Query("q")

        var entries []citation.Entry
        if typ == "" && status == "" && area == "" && query == "" {
                entries = h.Registry.All()
        } else {
                entries = h.Registry.Filter(typ, status, area, query)
        }

        c.JSON(http.StatusOK, gin.H{
                "count":   len(entries),
                "entries": entries,
        })
}

func (h *CitationHandler) SoftwareCitation(c *gin.Context) {
        format := c.DefaultQuery("format", "csljson")
        if format != "bibtex" && format != "ris" && format != "csljson" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid format: must be bibtex, ris, or csljson"})
                return
        }

        title := "DNS Tool: Domain Security Audit Platform"
        version := h.Config.AppVersion
        doi := "10.5281/zenodo.18854899"
        url := "https://dnstool.it-help.tech"
        authorFamily := "Balboa"
        authorGiven := "Carey James"
        date := "2026-03-09"

        if cff := loadCitationCFF(); cff != nil {
                if cff.Title != "" {
                        title = cff.Title
                }
                if cff.Version != "" {
                        version = cff.Version
                }
                if cff.DOI != "" {
                        doi = cff.DOI
                }
                if cff.URL != "" {
                        url = cff.URL
                }
                if cff.DateReleased != "" {
                        date = cff.DateReleased
                }
                if len(cff.Authors) > 0 {
                        authorFamily = cff.Authors[0].FamilyNames
                        authorGiven = cff.Authors[0].GivenNames
                }
        }

        switch format {
        case "bibtex":
                out := citation.SoftwareToBibTeX(title, version, doi, url, authorFamily, authorGiven, date)
                c.Header("Content-Disposition", `attachment; filename="dnstool.bib"`)
                c.Data(http.StatusOK, "application/x-bibtex; charset=utf-8", []byte(out))
        case "ris":
                out := citation.SoftwareToRIS(title, version, doi, url, authorFamily, authorGiven, date)
                c.Header("Content-Disposition", `attachment; filename="dnstool.ris"`)
                c.Data(http.StatusOK, "application/x-research-info-systems; charset=utf-8", []byte(out))
        default:
                out, err := citation.SoftwareToCSLJSON(title, version, doi, url, authorFamily, authorGiven, date)
                if err != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
                        return
                }
                c.Header("Content-Disposition", `attachment; filename="dnstool.json"`)
                c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(out))
        }
}

func (h *CitationHandler) AnalysisCitation(c *gin.Context) {
        format := c.DefaultQuery("format", "csljson")
        if format != "bibtex" && format != "ris" && format != "csljson" {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid format: must be bibtex, ris, or csljson"})
                return
        }
        idStr := c.Param("id")

        id, err := strconv.ParseInt(idStr, 10, 32)
        if err != nil || id <= 0 {
                c.JSON(http.StatusBadRequest, gin.H{"error": "invalid analysis ID"})
                return
        }

        analysis, err := h.DB.Queries.GetAnalysisByID(c.Request.Context(), int32(id))
        if err != nil {
                c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
                return
        }

        if !h.checkCitationAccess(c, analysis.ID, analysis.Private) {
                c.JSON(http.StatusNotFound, gin.H{"error": "analysis not found"})
                return
        }

        manifestEntries := h.buildAnalysisManifest(analysis.FullResults)
        safeID := safeFilenameRe.ReplaceAllString(idStr, "")

        switch format {
        case "bibtex":
                out := citation.EntriesToBibTeX(manifestEntries)
                c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="analysis-%s.bib"`, safeID))
                c.Data(http.StatusOK, "application/x-bibtex; charset=utf-8", []byte(out))
        case "ris":
                out := citation.EntriesToRIS(manifestEntries)
                c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="analysis-%s.ris"`, safeID))
                c.Data(http.StatusOK, "application/x-research-info-systems; charset=utf-8", []byte(out))
        default:
                out, err := citation.EntriesToCSLJSON(manifestEntries)
                if err != nil {
                        c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
                        return
                }
                c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="analysis-%s.json"`, safeID))
                c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(out))
        }
}

func (h *CitationHandler) checkCitationAccess(c *gin.Context, analysisID int32, private bool) bool {
        if !private {
                return true
        }
        auth, exists := c.Get(mapKeyAuthenticated)
        if !exists || auth != true {
                return false
        }
        uid, ok := c.Get(mapKeyUserId)
        if !ok {
                return false
        }
        userID, ok := uid.(int32)
        if !ok {
                return false
        }
        isOwner, err := h.DB.Queries.CheckAnalysisOwnership(c.Request.Context(), dbq.CheckAnalysisOwnershipParams{
                AnalysisID: analysisID,
                UserID:     userID,
        })
        return err == nil && isOwner
}

func (h *CitationHandler) buildAnalysisManifest(fullResults json.RawMessage) []citation.ManifestEntry {
        return buildCitationManifestFromResults(fullResults)
}

func buildCitationManifestFromResults(fullResults json.RawMessage) []citation.ManifestEntry {
        reg := citation.Global()
        m := citation.NewManifest()

        var results map[string]any
        if err := json.Unmarshal(fullResults, &results); err != nil {
                return nil
        }

        if _, ok := results["spf_analysis"]; ok {
                m.Cite("rfc:7208")
        }
        if _, ok := results["dmarc_analysis"]; ok {
                m.Cite("rfc:7489")
        }
        if _, ok := results["dkim_analysis"]; ok {
                m.Cite("rfc:6376")
                m.Cite("rfc:8301")
        }
        if _, ok := results["dnssec_analysis"]; ok {
                m.Cite("rfc:4033")
                m.Cite("rfc:4034")
                m.Cite("rfc:4035")
        }
        if _, ok := results["dane_analysis"]; ok {
                m.Cite("rfc:6698")
                m.Cite("rfc:7672")
        }
        if _, ok := results["mta_sts_analysis"]; ok {
                m.Cite("rfc:8461")
        }
        if _, ok := results["tlsrpt_analysis"]; ok {
                m.Cite("rfc:8460")
        }
        if _, ok := results["bimi_analysis"]; ok {
                m.Cite("rfc:9495")
        }
        if _, ok := results["caa_analysis"]; ok {
                m.Cite("rfc:8659")
        }
        if _, ok := results["ns_records"]; ok {
                m.Cite("rfc:1034")
                m.Cite("rfc:1035")
        }

        if rem, ok := results["remediation"].(map[string]any); ok {
                extractRemCitations(rem, m)
        }

        m.Cite("nist:800-177")
        m.Cite("odni:icd-203")

        return m.Entries(reg)
}

func extractRemCitations(rem map[string]any, m *citation.Manifest) {
        sections, ok := rem["per_section"].(map[string]any)
        if !ok {
                return
        }
        for _, v := range sections {
                fixes, ok := v.([]any)
                if !ok {
                        continue
                }
                for _, f := range fixes {
                        fix, ok := f.(map[string]any)
                        if !ok {
                                continue
                        }
                        if rfc, ok := fix["rfc"].(string); ok && rfc != "" {
                                citID := rfcLabelToSectionID(rfc)
                                if citID != "" {
                                        m.Cite(citID)
                                }
                        }
                }
        }
}

func rfcLabelToSectionID(label string) string {
        label = strings.TrimSpace(label)
        if !strings.HasPrefix(label, "RFC ") {
                return ""
        }
        rest := strings.TrimPrefix(label, "RFC ")
        parts := strings.SplitN(rest, " ", 2)
        num := parts[0]

        if idx := strings.Index(num, "\u00a7"); idx != -1 {
                section := num[idx+len("\u00a7"):]
                num = num[:idx]
                return "rfc:" + strings.TrimSpace(num) + "\u00a7" + strings.TrimSpace(section)
        }

        if len(parts) > 1 {
                after := strings.TrimSpace(parts[1])
                if strings.HasPrefix(after, "\u00a7") {
                        section := strings.TrimPrefix(after, "\u00a7")
                        return "rfc:" + strings.TrimSpace(num) + "\u00a7" + strings.TrimSpace(section)
                }
        }

        return "rfc:" + strings.TrimSpace(num)
}
