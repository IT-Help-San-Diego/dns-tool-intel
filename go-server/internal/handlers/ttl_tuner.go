package handlers

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"dnstool/go-server/internal/analyzer"
	"dnstool/go-server/internal/config"
	"dnstool/go-server/internal/icuae"

	"github.com/gin-gonic/gin"
)

const tplTTLTuner = "ttl_tuner.html"

type TTLTunerHandler struct {
	Config   *config.Config
	Analyzer *analyzer.Analyzer
}

func NewTTLTunerHandler(cfg *config.Config, a *analyzer.Analyzer) *TTLTunerHandler {
	return &TTLTunerHandler{Config: cfg, Analyzer: a}
}

func (h *TTLTunerHandler) TTLTunerPage(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")
	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "ttl-tuner",
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, tplTTLTuner, data)
}

type TTLRecordResult struct {
	RecordType   string
	ObservedTTL  uint32
	TypicalTTL   uint32
	Status       string
	StatusClass  string
	Locked       bool
	LockReason   string
	Recommendation string
	QueryReduction string
	PropagationNote string
	CloudflareUI   string
	Route53JSON    string
	BINDSnippet    string
	GenericStep    string
}

type TTLTunerResult struct {
	Domain         string
	Provider       string
	Profile        icuae.ProviderProfile
	HasProvider    bool
	Records        []TTLRecordResult
	MigrationTip   bool
	TotalReduction string
	ScanTime       string
}

var tunerRecordTypes = []string{
	"A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA",
}

func (h *TTLTunerHandler) AnalyzeTTL(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")
	csrfToken, _ := c.Get("csrf_token")

	domain := strings.TrimSpace(c.PostForm("domain"))
	profile := strings.TrimSpace(c.PostForm("profile"))
	if profile == "" {
		profile = "stability"
	}

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"BetaPages":       h.Config.BetaPages,
		"CspNonce":        nonce,
		"CsrfToken":       csrfToken,
		"ActivePage":      "ttl-tuner",
		"Domain":          domain,
		"Profile":         profile,
	}
	mergeAuthData(c, h.Config, data)

	if domain == "" {
		data["Error"] = "Please enter a domain name to analyze."
		c.HTML(http.StatusOK, tplTTLTuner, data)
		return
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.Split(domain, "/")[0]

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	nsResult := h.Analyzer.DNS.QueryDNS(ctx, "NS", domain)
	providerName := icuae.DetectDNSProvider(nil, nsResult)
	provProfile, hasProvider := icuae.GetProviderProfile(providerName)

	var records []TTLRecordResult
	totalOldQueries := 0.0
	totalNewQueries := 0.0

	for _, rt := range tunerRecordTypes {
		result := h.Analyzer.DNS.QueryDNSWithTTL(ctx, rt, domain)
		if len(result.Records) == 0 {
			continue
		}

		var observedTTL uint32
		if result.TTL != nil {
			observedTTL = *result.TTL
		}

		typical := ttlForProfile(rt, profile)

		rec := buildTunerRecord(rt, observedTTL, typical, providerName, provProfile, hasProvider, profile)
		records = append(records, rec)

		if observedTTL > 0 {
			totalOldQueries += 86400.0 / float64(observedTTL)
		}
		if typical > 0 {
			totalNewQueries += 86400.0 / float64(typical)
		}
	}

	reduction := ""
	if totalOldQueries > 0 && totalNewQueries > 0 {
		diff := totalOldQueries - totalNewQueries
		pct := (diff / totalOldQueries) * 100
		if pct > 0 {
			reduction = fmt.Sprintf("%.0f%% fewer DNS queries per day", pct)
		} else if pct < 0 {
			reduction = fmt.Sprintf("%.0f%% more DNS queries per day (for faster propagation)", math.Abs(pct))
		}
	}

	hasMigrationCandidate := false
	for _, r := range records {
		if r.RecordType == "A" || r.RecordType == "AAAA" {
			hasMigrationCandidate = true
			break
		}
	}

	sort.Slice(records, func(i, j int) bool {
		order := map[string]int{"A": 0, "AAAA": 1, "CNAME": 2, "MX": 3, "TXT": 4, "NS": 5, "CAA": 6, "SOA": 7}
		return order[records[i].RecordType] < order[records[j].RecordType]
	})

	tunerResult := TTLTunerResult{
		Domain:         domain,
		Provider:       providerName,
		Profile:        provProfile,
		HasProvider:    hasProvider,
		Records:        records,
		MigrationTip:   hasMigrationCandidate,
		TotalReduction: reduction,
		ScanTime:       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}

	data["Result"] = tunerResult
	c.HTML(http.StatusOK, tplTTLTuner, data)
}

func ttlForProfile(recordType, profile string) uint32 {
	stability := map[string]uint32{
		"A": 3600, "AAAA": 3600, "MX": 3600, "TXT": 3600,
		"NS": 86400, "CNAME": 3600, "CAA": 3600, "SOA": 3600,
	}
	agility := map[string]uint32{
		"A": 300, "AAAA": 300, "MX": 1800, "TXT": 300,
		"NS": 3600, "CNAME": 300, "CAA": 3600, "SOA": 3600,
	}
	if profile == "agility" {
		if v, ok := agility[recordType]; ok {
			return v
		}
	}
	if v, ok := stability[recordType]; ok {
		return v
	}
	return icuae.TypicalTTLFor(recordType)
}

func buildTunerRecord(rt string, observed, typical uint32, providerName string, profile icuae.ProviderProfile, hasProvider bool, profileName string) TTLRecordResult {
	rec := TTLRecordResult{
		RecordType:  rt,
		ObservedTTL: observed,
		TypicalTTL:  typical,
	}

	rec.CloudflareUI = fmt.Sprintf("DNS → Records → Edit %s record → TTL → Set to %s", rt, formatHumanTTL(typical))
	rec.Route53JSON = buildRoute53JSON(rt, typical)
	rec.BINDSnippet = fmt.Sprintf("%-20s %d IN %s <value>", "@", typical, rt)
	rec.GenericStep = fmt.Sprintf("Find your %s record in your DNS provider's dashboard. Change the TTL value to %d seconds (%s).", rt, typical, formatHumanTTL(typical))

	locked, lockReason := checkProviderLock(rt, observed, providerName, profile, hasProvider)
	rec.Locked = locked
	rec.LockReason = lockReason

	if locked {
		rec.Status = "Provider-Locked"
		rec.StatusClass = "secondary"
		rec.Recommendation = lockReason
	} else if observed == typical {
		rec.Status = "Optimal"
		rec.StatusClass = "success"
		rec.Recommendation = "No change needed — this TTL is already at the recommended value."
	} else if observed == 0 {
		rec.Status = "Not Set"
		rec.StatusClass = "warning"
		rec.Recommendation = fmt.Sprintf("Set TTL to %d seconds (%s) per %s profile.", typical, formatHumanTTL(typical), profileName)
	} else {
		ratio := float64(observed) / float64(typical)
		if ratio >= 0.5 && ratio <= 2.0 {
			rec.Status = "Acceptable"
			rec.StatusClass = "info"
			rec.Recommendation = fmt.Sprintf("Current TTL is acceptable. For optimal %s, consider %d seconds (%s).", profileName, typical, formatHumanTTL(typical))
		} else {
			rec.Status = "Adjust"
			rec.StatusClass = "warning"
			if observed > typical {
				rec.Recommendation = fmt.Sprintf("TTL is higher than recommended. Reduce to %d seconds (%s) for better %s.", typical, formatHumanTTL(typical), profileName)
			} else {
				rec.Recommendation = fmt.Sprintf("TTL is lower than recommended. Increase to %d seconds (%s) to reduce query volume.", typical, formatHumanTTL(typical))
			}
		}
	}

	if observed > 0 && typical > 0 {
		oldPerDay := 86400.0 / float64(observed)
		newPerDay := 86400.0 / float64(typical)
		diff := oldPerDay - newPerDay
		if math.Abs(diff) > 1 {
			pct := (diff / oldPerDay) * 100
			if pct > 0 {
				rec.QueryReduction = fmt.Sprintf("%.0f%% fewer queries/day", pct)
			} else {
				rec.QueryReduction = fmt.Sprintf("%.0f%% more queries/day (faster propagation)", math.Abs(pct))
			}
		}
	}

	if rt == "A" || rt == "AAAA" {
		if observed > 3600 {
			rec.PropagationNote = fmt.Sprintf("Current TTL of %s means IP changes take up to %s to propagate globally.", formatHumanTTL(observed), formatHumanTTL(observed))
		} else if observed > 0 && observed <= 300 {
			rec.PropagationNote = fmt.Sprintf("Current TTL of %s gives fast propagation (under 5 minutes) but generates more DNS queries.", formatHumanTTL(observed))
		}
	}

	return rec
}

func checkProviderLock(rt string, observed uint32, providerName string, profile icuae.ProviderProfile, hasProvider bool) (bool, string) {
	if !hasProvider {
		return false, ""
	}

	if providerName == "Cloudflare" && (rt == "A" || rt == "AAAA") && observed == profile.ProxiedTTL {
		return true, fmt.Sprintf(
			"Cloudflare enforces a fixed TTL of %s for proxied (orange-cloud) records. "+
				"You cannot change this TTL while the record is proxied. "+
				"To regain TTL control, disable proxying (switch to gray cloud) — but you'll lose Cloudflare's CDN and DDoS protection.",
			formatHumanTTL(profile.ProxiedTTL),
		)
	}

	if providerName == "AWS Route 53" && (rt == "A" || rt == "AAAA") && (observed == profile.AliasTTL || observed == 0) {
		return true, fmt.Sprintf(
			"AWS Route 53 alias records have a fixed TTL of %s when pointing to AWS resources (ELB, CloudFront, S3). "+
				"To set a custom TTL, use a standard A/AAAA record instead of an alias.",
			formatHumanTTL(profile.AliasTTL),
		)
	}

	if profile.MinAllowedTTL > 0 {
		return false, fmt.Sprintf("Note: %s enforces a minimum TTL of %s.", providerName, formatHumanTTL(profile.MinAllowedTTL))
	}

	return false, ""
}

func formatHumanTTL(ttl uint32) string {
	if ttl >= 86400 && ttl%86400 == 0 {
		d := ttl / 86400
		if d == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", d)
	}
	if ttl >= 3600 && ttl%3600 == 0 {
		h := ttl / 3600
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	if ttl >= 60 && ttl%60 == 0 {
		m := ttl / 60
		if m == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", m)
	}
	return fmt.Sprintf("%d seconds", ttl)
}

func buildRoute53JSON(rt string, ttl uint32) string {
	return fmt.Sprintf(`{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "<domain>",
      "Type": "%s",
      "TTL": %d,
      "ResourceRecords": [{"Value": "<value>"}]
    }
  }]
}`, rt, ttl)
}
