// dns-tool:scrutiny science
// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

package analyzer

import (
        "context"
        "fmt"
        "net"
        "strings"
        "time"
)

const (
        nameGoogleWorkspace = "Google Workspace"
        nameMicrosoft365    = "Microsoft 365"
        nameCloudflare      = "Cloudflare"
        nameCSCGlobalDNS    = "CSC Global DNS"
        nameDigitalOcean    = "DigitalOcean"
        nameGoDaddy         = "GoDaddy"
        nameLinode           = "Linode"
        nameNamecheap       = "Namecheap"
        nameAmazonRoute53   = "Amazon Route 53"

        infraStatus       = "status"
        infraSuccess      = "success"
        infraUnknown      = "Unknown"
        infraDetectedFrom = "detected_from"
        infraSources      = "sources"
        infraCapabilities = "capabilities"
        infraConfidence   = "confidence"
        infraHosting      = "hosting"
        infraGoogle       = "google"
        infraCloudflare   = "cloudflare"
        infraDigitalocean = "digitalocean"
        infraVultr        = "vultr"
        infraLinode       = "linode"
        infraHetzner      = "hetzner"
        nsLabel           = "NS"
)

var enterpriseProviders = map[string]providerInfo{
        "awsdns": {
                Name:     nameAmazonRoute53,
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featGlobalInfra},
        },
        "route53": {
                Name:     nameAmazonRoute53,
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featGlobalInfra},
        },
        "cloudflare": {
                Name:     nameCloudflare,
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featProtectedInfra},
        },
        "azure-dns": {
                Name:     "Azure DNS",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featGlobalInfra, featEnterpriseSecurity},
        },
        "ultradns": {
                Name:     "UltraDNS",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
        },
        "dynect": {
                Name:     "Oracle Dyn",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
        },
        "nsone": {
                Name:     "NS1",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
        },
        "google": {
                Name:     "Google Cloud DNS",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featGlobalInfra, featEnterpriseSecurity},
        },
        "cscglobal": {
                Name:     nameCSCGlobalDNS,
                Tier:     tierEnterprise,
                Features: []string{featBrandProtection, featEnterpriseManagement, featEnterpriseSecurity},
        },
        "cscdns": {
                Name:     nameCSCGlobalDNS,
                Tier:     tierEnterprise,
                Features: []string{featBrandProtection, featEnterpriseManagement, featEnterpriseSecurity},
        },
        "akamai": {
                Name:     "Akamai Edge DNS",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseSecurity},
        },
        "akam": {
                Name:     "Akamai Edge DNS",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseSecurity},
        },
        "domaincontrol": {
                Name:     "GoDaddy",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
        },
        "godaddy": {
                Name:     "GoDaddy",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection, featEnterpriseManagement},
        },
        "registrar-servers": {
                Name:     "Namecheap",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featEnterpriseManagement},
        },
        "dns.he.net": {
                Name:     "Hurricane Electric",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featGlobalInfra},
        },
        "hetzner": {
                Name:     "Hetzner",
                Tier:     tierEnterprise,
                Features: []string{featGlobalInfra, featEnterpriseManagement},
        },
        "digitalocean": {
                Name:     "DigitalOcean",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featGlobalInfra},
        },
        "vultr": {
                Name:     "Vultr",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featGlobalInfra},
        },
        "dnsimple": {
                Name:     "DNSimple",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featEnterpriseManagement},
        },
        "netlify": {
                Name:     "Netlify",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection},
        },
        "vercel": {
                Name:     "Vercel",
                Tier:     tierEnterprise,
                Features: []string{featGlobalAnycast, featDDoSProtection},
        },
}

var legacyProviderBlocklist = map[string]bool{
        "networksolutions": true,
        "worldnic":         true,
        "bluehost":         true,
        "hostgator":        true,
        "ipage":            true,
        "fatcow":           true,
        "justhost":         true,
        "hostmonster":      true,
        "arvixe":           true,
        "site5":            true,
}

var selfHostedEnterprise = map[string]providerInfo{
        "ns.apple.com":  {Name: "Apple (Self-Hosted)", Tier: tierEnterprise, Features: []string{featSelfManagedInfra, featGlobalAnycast, featEnterpriseSecurity}},
        "microsoft.com": {Name: "Microsoft (Self-Hosted)", Tier: tierEnterprise, Features: []string{featSelfManagedInfra, featGlobalAnycast, featEnterpriseSecurity}},
        "facebook.com":  {Name: "Meta (Self-Hosted)", Tier: tierEnterprise, Features: []string{featSelfManagedInfra, featGlobalAnycast, featEnterpriseSecurity}},
        "amazon.com":    {Name: "Amazon (Self-Hosted)", Tier: tierEnterprise, Features: []string{featSelfManagedInfra, featGlobalAnycast, featEnterpriseSecurity}},
}

var governmentDomains = map[string]providerInfo{
        ".gov":    {Name: "U.S. Government", Tier: tierEnterprise, Features: []string{featGovSecurityStandards, "FISMA compliance", featProtectedInfra}},
        ".mil":    {Name: "U.S. Military", Tier: tierEnterprise, Features: []string{"Military security standards", "DoD compliance", featProtectedInfra}},
        ".gov.uk": {Name: "UK Government", Tier: tierEnterprise, Features: []string{featGovSecurityStandards, "NCSC compliance", featProtectedInfra}},
        ".gov.au": {Name: "Australian Government", Tier: tierEnterprise, Features: []string{featGovSecurityStandards, "ASD compliance", featProtectedInfra}},
        ".gc.ca":  {Name: "Canadian Government", Tier: tierEnterprise, Features: []string{featGovSecurityStandards, "GC compliance", featProtectedInfra}},
}

var managedProviders = map[string]providerInfo{
        "digitalocean":      {Name: nameDigitalOcean, Tier: tierManaged},
        "linode":            {Name: nameLinode, Tier: tierManaged},
        "vultr":             {Name: "Vultr", Tier: tierManaged},
        "porkbun":           {Name: "Porkbun", Tier: tierManaged},
        "namecheap":         {Name: nameNamecheap, Tier: tierManaged},
        "registrar-servers": {Name: nameNamecheap, Tier: tierManaged},
        "godaddy":           {Name: nameGoDaddy, Tier: tierManaged},
        "domaincontrol":     {Name: nameGoDaddy, Tier: tierManaged},
}

var hostingProviders = map[string]string{
        infraCloudflare: nameCloudflare, "amazon": "AWS", "azure": "Azure",
        infraGoogle: "Google Cloud", infraDigitalocean: nameDigitalOcean,
        infraLinode: nameLinode, infraVultr: "Vultr", infraHetzner: "Hetzner",
        "ovh": "OVH", "netlify": "Netlify", "vercel": "Vercel",
        "heroku": "Heroku", "github": "GitHub Pages",
        "squarespace": "Squarespace", "wix": "Wix", "shopify": "Shopify",
}

var hostingPTRProviders = map[string]string{
        "cloudfront.net":           "AWS CloudFront",
        "amazonaws.com":            "AWS",
        "awsglobalaccelerator.com": "AWS Global Accelerator",
        infraCloudflare:            nameCloudflare,
        "azure":                    "Azure",
        infraGoogle:                "Google Cloud",
        infraDigitalocean:          nameDigitalOcean,
        infraLinode:                nameLinode,
        infraVultr:                 "Vultr",
        infraHetzner:               "Hetzner",
        "ovh":                      "OVH",
        "netlify":                  "Netlify",
        "vercel":                   "Vercel",
        "heroku":                   "Heroku",
        "github":                   "GitHub Pages",
        "squarespace":              "Squarespace",
        "shopify":                  "Shopify",
        "akamai":                   "Akamai",
        "fastly":                   "Fastly",
        "edgecastcdn":              "Edgecast/Verizon",
        "stackpath":                "StackPath",
}

var dnsHostingProviders = map[string]string{
        infraCloudflare: nameCloudflare, "awsdns": nameAmazonRoute53,
        "azure-dns": "Azure DNS", infraGoogle: "Google Cloud DNS",
        "ultradns": "Vercara UltraDNS", "nsone": "NS1",
        infraDigitalocean: nameDigitalOcean, infraLinode: nameLinode,
        "domaincontrol": nameGoDaddy, "registrar-servers": nameNamecheap,
        "cscdns": nameCSCGlobalDNS, "csc.com": nameCSCGlobalDNS,
        "netnames": nameCSCGlobalDNS,
        "akam": "Akamai Edge DNS", "dynect": "Oracle Dyn",
        "verisign": "Verisign DNS", "markmonitor": "MarkMonitor DNS",
        "porkbun": "Porkbun", infraVultr: "Vultr",
}

var emailHostingProviders = map[string]string{
        infraGoogle: "Google Workspace", "outlook": "Microsoft 365",
        "protection.outlook": "Microsoft 365", "zoho": "Zoho Mail",
        "protonmail": "ProtonMail", "fastmail": "Fastmail",
        "mx.cloudflare": "Cloudflare Email",
}

var hostedMXProviders = map[string]bool{
        providerGoogleWS:        true,
        providerMicrosoft365:    true,
        providerZohoMail:        true,
        providerFastmail:        true,
        providerProtonMail:      true,
        providerCloudflareEmail: true,
}

var mxProviderPatterns = map[string]string{
        "google":             nameGoogleWorkspace,
        "googlemail":         nameGoogleWorkspace,
        "gmail":              nameGoogleWorkspace,
        "outlook":            nameMicrosoft365,
        "microsoft":          nameMicrosoft365,
        "protection.outlook": nameMicrosoft365,
        "pphosted":           "Proofpoint",
        "iphmx":              "Proofpoint",
        "mimecast":           "Mimecast",
        "barracuda":          "Barracuda",
        "sophos":             "Sophos",
        "zoho":               "Zoho Mail",
        "mailgun":            "Mailgun",
        "sendgrid":           "SendGrid",
        "amazonses":          "Amazon SES",
        "fastmail":           "Fastmail",
        "protonmail":         "Proton Mail",
        "yahoodns":           "Yahoo Mail",
        "icloud":             "iCloud Mail",
        "hover":              "Hover",
        "migadu":             "Migadu",
        "pobox":              "Pobox",
        "rackspace":          "Rackspace Email",
        "emailsrvr":          "Rackspace Email",
        "secureserver":       "GoDaddy Email",
        "forcepoint":         "Forcepoint",
        "messagelabs":        "Symantec",
        "hornetsecurity":     "Hornetsecurity",
        "spamexperts":        "SpamExperts",
        "antispamcloud":      "SpamExperts",
}

var nsProviderPatterns = map[string]string{
        "cloudflare":        "Cloudflare",
        "awsdns":            nameAmazonRoute53,
        "route53":           nameAmazonRoute53,
        "google":            "Google Cloud DNS",
        "azure-dns":         "Azure DNS",
        "digitalocean":      "DigitalOcean",
        "linode":            "Linode",
        "godaddy":           "GoDaddy",
        "domaincontrol":     "GoDaddy",
        "namecheap":         "Namecheap",
        "registrar-servers": "Namecheap",
        "hetzner":           "Hetzner",
        "vultr":             "Vultr",
        "dynect":            "Oracle Dyn",
        "ultradns":          "UltraDNS",
        "nsone":             "NS1",
        "dns.he.net":        "Hurricane Electric",
        "dnsimple":          "DNSimple",
        "hover":             "Hover",
        "squarespace":       "Squarespace",
        "wix":               "Wix",
        "vercel":            "Vercel",
        "netlify":           "Netlify",
}

var webHostingPatterns = map[string]string{
        "cloudflare":         "Cloudflare",
        "amazonaws":          "AWS",
        "cloudfront":         "AWS CloudFront",
        "azurewebsites":      "Azure",
        "azure":              "Azure",
        "herokuapp":          "Heroku",
        "netlify":            "Netlify",
        "vercel":             "Vercel",
        "squarespace":        "Squarespace",
        "wix":                "Wix",
        "shopify":            "Shopify",
        "wpengine":           "WP Engine",
        "pantheon":           "Pantheon",
        "github.io":          "GitHub Pages",
        "fastly":             "Fastly",
        "akamai":             "Akamai",
        "digitalocean":       "DigitalOcean",
        "linode":             "Linode",
        "hetzner":            "Hetzner",
        "ovh":                "OVH",
        "googleusercontent":  provGoogleCloud,
        "1e100.net":          provGoogleCloud,
}

var ptrHostingPatterns = map[string]string{
        "amazonaws.com":        "AWS",
        "compute.amazonaws":    "AWS",
        "ec2":                  "AWS",
        "cloudfront.net":       "AWS CloudFront",
        "azure":                "Azure",
        "googleusercontent":    provGoogleCloud,
        "1e100.net":            provGoogleCloud,
        "bc.googleusercontent": provGoogleCloud,
        "digitalocean.com":     "DigitalOcean",
        "linode.com":           "Linode",
        "vultr.com":            "Vultr",
        "hetzner":              "Hetzner",
        "ovh.net":              "OVH",
        "rackspace":            "Rackspace",
}

func (a *Analyzer) AnalyzeDNSInfrastructure(domain string, results map[string]any) map[string]any {
        basic, _ := results["basic_records"].(map[string]any)
        nsRecords, _ := basic["NS"].([]string)

        im := matchEnterpriseProvider(nsRecords)
        if im != nil && im.provider != nil {
                altItems := collectAltSecurityItems(results)
                explainsDNSSEC := false
                dnssec, _ := results["dnssec"].(map[string]any)
                if dnssec != nil {
                        status, _ := dnssec["status"].(string)
                        if status != "success" {
                                explainsDNSSEC = true
                        }
                }
                return map[string]any{
                        "provider_tier":      tierEnterprise,
                        "provider":           im.provider.Name,
                        "provider_features":  im.provider.Features,
                        "is_government":      false,
                        "alt_security_items": altItems,
                        "explains_no_dnssec": explainsDNSSEC,
                        "assessment":         "Enterprise-grade DNS infrastructure",
                }
        }

        return map[string]any{
                "provider_tier":      "standard",
                "provider_features":  []string{},
                "is_government":      false,
                "alt_security_items": []string{},
                "assessment":         "Standard DNS",
        }
}

func (a *Analyzer) GetHostingInfo(ctx context.Context, domain string, results map[string]any) map[string]any {
        basic, _ := results["basic_records"].(map[string]any)
        mxRecords, _ := basic["MX"].([]string)
        nsRecords, _ := basic["NS"].([]string)
        isNoMail := results["has_null_mx"] == true || results["is_no_mail_domain"] == true

        emailHosting := identifyEmailProvider(mxRecords)
        dnsHosting := identifyDNSProvider(nsRecords)
        hosting := identifyWebHosting(basic)

        hosting, dnsHosting, emailHosting = applyHostingDefaults(hosting, dnsHosting, emailHosting, isNoMail)

        return map[string]any{
                "hosting":            hosting,
                "dns_hosting":        dnsHosting,
                "email_hosting":      emailHosting,
                "domain":             domain,
                "hosting_confidence": map[string]any{},
                "dns_confidence":     map[string]any{},
                "email_confidence":   map[string]any{},
                "dns_from_parent":    false,
        }
}

func (a *Analyzer) DetectEmailSecurityManagement(spf, dmarc, tlsrpt, mtasts map[string]any, domain string, dkim map[string]any) map[string]any {
        providers := make(map[string]map[string]any)

        detectDMARCReportProviders(providers, dmarc)
        detectTLSRPTReportProviders(providers, tlsrpt)
        spfFlattening := detectSPFFlatteningProvider(providers, spf)
        detectMTASTSManagement(providers, mtasts)
        a.detectHostedDKIMProviders(providers, domain, dkim)
        a.detectDynamicServices(providers, domain)

        providerList := make([]map[string]any, 0, len(providers))
        for _, prov := range providers {
                providerList = append(providerList, prov)
        }

        return map[string]any{
                "actively_managed": len(providers) > 0,
                "providers":        providerList,
                "spf_flattening":   spfFlattening,
                "provider_count":   len(providerList),
                "confidence":       ConfidenceInferredMap(MethodDMARCRua),
        }
}

func enrichHostingFromEdgeCDN(results map[string]any) {
        hostingSummary, _ := results["hosting_summary"].(map[string]any)
        if hostingSummary == nil {
                return
        }
        hosting, _ := hostingSummary[infraHosting].(string)
        if hosting != infraUnknown {
                return
        }
        edgeCDN, _ := results["edge_cdn"].(map[string]any)
        if edgeCDN == nil {
                return
        }
        isBehindCDN, _ := edgeCDN["is_behind_cdn"].(bool)
        cdnProvider, _ := edgeCDN["cdn_provider"].(string)
        if !isBehindCDN || cdnProvider == "" {
                return
        }
        hostingSummary[infraHosting] = cdnProvider + " (CDN)"
        hostingSummary["hosting_confidence"] = ConfidenceInferredMap(MethodASNMatch)
}

func matchEnterpriseProvider(nsList []string) *infraMatch {
        for _, ns := range nsList {
                nsLower := strings.ToLower(ns)
                for blocked := range legacyProviderBlocklist {
                        if strings.Contains(nsLower, blocked) {
                                return nil
                        }
                }
        }
        for _, ns := range nsList {
                nsLower := strings.ToLower(ns)
                for pattern, info := range enterpriseProviders {
                        if strings.Contains(nsLower, pattern) {
                                p := info
                                return &infraMatch{provider: &p, tier: tierEnterprise}
                        }
                }
        }
        return nil
}

func matchSelfHostedProvider(nsStr string) *infraMatch {
        for key, info := range selfHostedEnterprise {
                if strings.Contains(nsStr, key) {
                        return &infraMatch{provider: &info, tier: tierEnterprise}
                }
        }
        return nil
}

func matchManagedProvider(nsStr string) *infraMatch {
        for key, info := range managedProviders {
                if strings.Contains(nsStr, key) {
                        return &infraMatch{provider: &info, tier: tierManaged}
                }
        }
        return nil
}

func matchGovernmentDomain(domain string) (*infraMatch, bool) {
        for suffix, info := range governmentDomains {
                if strings.HasSuffix(domain, suffix) {
                        return &infraMatch{provider: &info, tier: tierEnterprise}, true
                }
        }
        return nil, false
}

func collectAltSecurityItems(results map[string]any) []string {
        var items []string
        caaAnalysis, _ := results["caa_analysis"].(map[string]any)
        dnssecAnalysis, _ := results["dnssec_analysis"].(map[string]any)

        if caaAnalysis != nil && caaAnalysis[infraStatus] == infraSuccess {
                items = append(items, "CAA records configured")
        }
        if dnssecAnalysis != nil && dnssecAnalysis[infraStatus] == infraSuccess {
                items = append(items, "DNSSEC validated")
        }
        return items
}

func assessTier(tier string) string {
        switch tier {
        case tierEnterprise:
                return "Enterprise-grade DNS infrastructure"
        case tierManaged:
                return "Managed DNS hosting"
        default:
                return "Standard DNS"
        }
}

func (a *Analyzer) resolveNSRecords(domain string, nsRecords []string) ([]string, bool) {
        if len(nsRecords) > 0 {
                return nsRecords, false
        }
        if a.DNS == nil {
                return nsRecords, false
        }
        parent := parentZone(domain)
        if parent == "" {
                return nsRecords, false
        }
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        parentNS := a.DNS.QueryDNS(ctx, nsLabel, parent)
        cancel()
        if len(parentNS) > 0 {
                return parentNS, true
        }
        return nsRecords, false
}

func matchAllProviders(nsList []string, nsStr string) *infraMatch {
        im := matchEnterpriseProvider(nsList)
        if im == nil {
                im = matchSelfHostedProvider(nsStr)
        }
        if im == nil {
                im = matchManagedProvider(nsStr)
        }
        return im
}

func buildInfraResult(im *infraMatch, isGovernment, nsFromParent bool, results map[string]any) map[string]any {
        providerTier := "standard"
        var providerFeatures []string
        if im != nil {
                providerTier = im.tier
                providerFeatures = im.provider.Features
        }

        result := map[string]any{
                "provider_tier":      providerTier,
                "provider_features":  providerFeatures,
                "is_government":      isGovernment,
                "alt_security_items": collectAltSecurityItems(results),
                "assessment":         assessTier(providerTier),
        }

        if im != nil {
                result["provider_name"] = im.provider.Name
                if nsFromParent {
                        result[infraConfidence] = ConfidenceInferredMap("Parent zone NS records")
                } else {
                        result[infraConfidence] = ConfidenceObservedMap(MethodNSPattern)
                }
        }
        if isGovernment {
                result["gov_confidence"] = ConfidenceInferredMap(MethodTLDSuffix)
        }

        return result
}

func (a *Analyzer) detectHostingFromPTR(ctx context.Context, aRecords []string) (string, bool) {
        if a.DNS == nil {
                return "", false
        }
        for _, ip := range aRecords {
                arpaName := buildArpaName(ip)
                if arpaName == "" {
                        continue
                }
                ptrCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
                ptrRecords := a.DNS.QueryDNS(ptrCtx, "PTR", arpaName)
                cancel()
                for _, ptr := range ptrRecords {
                        ptr = strings.TrimSuffix(ptr, ".")
                        provider := detectProvider([]string{ptr}, hostingPTRProviders)
                        if provider != "" {
                                return provider, true
                        }
                }
        }
        return "", false
}

func (a *Analyzer) resolveDNSHosting(domain string, nsRecords []string) (string, bool) {
        dnsHosting := detectProvider(nsRecords, dnsHostingProviders)
        if dnsHosting != "" {
                return dnsHosting, false
        }
        parent := parentZone(domain)
        if parent == "" {
                return "", false
        }
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        parentNS := a.DNS.QueryDNS(ctx, nsLabel, parent)
        cancel()
        if len(parentNS) > 0 {
                dnsHosting = detectProvider(parentNS, dnsHostingProviders)
                if dnsHosting != "" {
                        return dnsHosting, true
                }
        }
        return "", false
}

func resolveEmailHosting(results map[string]any, mxRecords []string) (string, bool) {
        emailHosting := detectProvider(mxRecords, emailHostingProviders)
        if emailHosting != "" {
                return emailHosting, false
        }
        isNoMail := getBool(results, "is_no_mail_domain")
        if isNoMail {
                return "", false
        }
        emailHosting = detectEmailProviderFromSPF(results)
        return emailHosting, emailHosting != ""
}

func hostingConfidence(hosting string, fromPTR bool) map[string]any {
        if hosting == infraUnknown {
                return map[string]any{}
        }
        if fromPTR {
                return ConfidenceObservedMap(MethodPTRRecord)
        }
        return ConfidenceObservedMap(MethodARecordPattern)
}

func dnsConfidence(dnsFromParent bool) map[string]any {
        if dnsFromParent {
                return ConfidenceInferredMap("Parent zone NS records")
        }
        return ConfidenceObservedMap(MethodNSPattern)
}

func emailConfidence(emailFromSPF, isNoMail bool) map[string]any {
        if isNoMail {
                return ConfidenceObservedMap("SPF -all declares no mail")
        }
        if emailFromSPF {
                return ConfidenceObservedMap(MethodSPFInclude)
        }
        return ConfidenceObservedMap(MethodMXPattern)
}

func detectEmailProviderFromSPF(results map[string]any) string {
        spfData, _ := results["spf_analysis"].(map[string]any)
        if spfData == nil {
                return ""
        }
        validRecords, _ := spfData["valid_records"].([]string)
        if len(validRecords) == 0 {
                return ""
        }
        combined := strings.Join(validRecords, " ")
        return matchProviderFromRecords(combined, spfMailboxProviders)
}

func detectProvider(records []string, providers map[string]string) string {
        combined := strings.ToLower(strings.Join(records, " "))
        for key, name := range providers {
                if strings.Contains(combined, key) {
                        return name
                }
        }
        return ""
}

func matchMonitoringProvider(domain string) *managementProviderInfo {
        domainLower := strings.ToLower(domain)
        for pattern, info := range dmarcMonitoringProviders {
                if domainLower == pattern || strings.HasSuffix(domainLower, "."+pattern) {
                        result := info
                        return &result
                }
        }
        return nil
}

func detectDMARCReportProviders(providers map[string]map[string]any, dmarc map[string]any) {
        ruaStr := getStr(dmarc, "rua")
        rufStr := getStr(dmarc, "ruf")

        ruaDomains := extractMailtoDomains(ruaStr)
        rufDomains := extractMailtoDomains(rufStr)

        ruaDomainSet := make(map[string]bool)
        for _, d := range ruaDomains {
                ruaDomainSet[d] = true
        }
        rufDomainSet := make(map[string]bool)
        for _, d := range rufDomains {
                rufDomainSet[d] = true
        }

        allDomains := make(map[string]bool)
        for _, d := range ruaDomains {
                allDomains[d] = true
        }
        for _, d := range rufDomains {
                allDomains[d] = true
        }

        for domain := range allDomains {
                info := matchMonitoringProvider(domain)
                if info == nil {
                        continue
                }

                inRua := ruaDomainSet[domain]
                inRuf := rufDomainSet[domain]

                var source string
                switch {
                case inRua && inRuf:
                        source = "DMARC aggregate (rua) and forensic (ruf) reports"
                case inRuf:
                        source = "DMARC forensic reports (ruf)"
                default:
                        source = "DMARC aggregate reports (rua)"
                }
                addOrMergeProvider(providers, info, "DMARC", source)
        }
}

func detectTLSRPTReportProviders(providers map[string]map[string]any, tlsrpt map[string]any) {
        ruaStr := getStr(tlsrpt, "rua")
        domains := extractMailtoDomains(ruaStr)

        for _, domain := range domains {
                info := matchMonitoringProvider(domain)
                if info == nil {
                        continue
                }
                addOrMergeProvider(providers, info, "TLS-RPT", "TLS-RPT delivery reports")
        }
}

func detectSPFFlatteningProvider(providers map[string]map[string]any, spf map[string]any) map[string]any {
        includes, _ := spf["includes"].([]string)
        if len(includes) == 0 {
                return nil
        }

        for _, include := range includes {
                includeLower := strings.ToLower(include)
                for pattern, info := range spfFlatteningProviders {
                        if strings.HasSuffix(includeLower, pattern) || strings.Contains(includeLower, pattern) {
                                mpi := &managementProviderInfo{
                                        Name:         info.Name,
                                        Vendor:       info.Vendor,
                                        Capabilities: []string{"SPF management", "SPF flattening"},
                                }
                                addOrMergeProvider(providers, mpi, "SPF flattening", fmt.Sprintf("SPF flattening (include:%s)", include))

                                return map[string]any{
                                        "provider": info.Name,
                                        "vendor":   info.Vendor,
                                        "include":  include,
                                }
                        }
                }
        }
        return nil
}

func detectMTASTSManagement(providers map[string]map[string]any, mtasts map[string]any) {
        status := getStr(mtasts, "status")
        if status != "success" && status != "warning" {
                return
        }
        if getStr(mtasts, "record") == "" {
                return
        }

        hostingCNAME := getStr(mtasts, "hosting_cname")

        for name, prov := range providers {
                caps, _ := prov[infraCapabilities].([]string)
                if containsStr(caps, detMTASTS+" hosting") {
                        df, _ := prov[infraDetectedFrom].([]string)
                        if !containsStr(df, detMTASTS) {
                                providers[name][infraDetectedFrom] = append(df, detMTASTS)
                                sources, _ := prov[infraSources].([]string)
                                providers[name][infraSources] = append(sources, detMTASTS+" policy hosting")
                        }
                        return
                }
        }

        if hostingCNAME == "" {
                return
        }

        for pattern, info := range dmarcMonitoringProviders {
                if !containsStr(info.Capabilities, detMTASTS+" hosting") {
                        continue
                }
                if !strings.Contains(hostingCNAME, pattern) {
                        continue
                }
                mpi := &managementProviderInfo{
                        Name:         info.Name,
                        Vendor:       info.Vendor,
                        Capabilities: info.Capabilities,
                }
                addOrMergeProvider(providers, mpi, detMTASTS, fmt.Sprintf(detMTASTS+" hosting (CNAME: %s)", hostingCNAME))
                return
        }
}

func (a *Analyzer) detectHostedDKIMProviders(providers map[string]map[string]any, domain string, dkim map[string]any) {
        if domain == "" || dkim == nil {
                return
        }
        selectors, _ := dkim["selectors"].(map[string]any)
        if selectors == nil {
                return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        for selName := range selectors {
                dkimFQDN := selName + "." + domain
                cnames := a.DNS.QueryDNS(ctx, "CNAME", dkimFQDN)
                for _, cname := range cnames {
                        cnameLower := strings.ToLower(strings.TrimRight(cname, "."))
                        for cnamePattern, info := range hostedDKIMProviders {
                                if !strings.HasSuffix(cnameLower, cnamePattern) {
                                        continue
                                }
                                selShort := strings.ReplaceAll(selName, "._domainkey", "")
                                mpi := &managementProviderInfo{
                                        Name:         info.Name,
                                        Vendor:       info.Vendor,
                                        Capabilities: []string{"DKIM hosting"},
                                }
                                addOrMergeProvider(providers, mpi, "Hosted DKIM", fmt.Sprintf("Hosted DKIM (CNAME: %s → %s)", selShort, cnameLower))
                                break
                        }
                }
        }
}

func matchDynamicServiceNS(nsLower string) (dynamicServiceInfo, bool) {
        for nsPattern, dsInfo := range dynamicServicesProviders {
                if strings.HasSuffix(nsLower, nsPattern) {
                        return dsInfo, true
                }
        }
        return dynamicServiceInfo{}, false
}

func addDSDetection(detections map[string]*dsDetection, dsInfo dynamicServiceInfo, cap string) {
        if det, ok := detections[dsInfo.Name]; ok {
                if !containsStr(det.capabilities, cap) {
                        det.capabilities = append(det.capabilities, cap)
                }
        } else {
                detections[dsInfo.Name] = &dsDetection{
                        info:         dsInfo,
                        capabilities: []string{cap},
                }
        }
}

func (a *Analyzer) scanDynamicServiceZones(ctx context.Context, zones map[string]string) map[string]*dsDetection {
        detections := make(map[string]*dsDetection)
        for zoneKey, zoneFQDN := range zones {
                nsRecords := a.DNS.QueryDNS(ctx, nsLabel, zoneFQDN)
                for _, ns := range nsRecords {
                        nsLower := strings.ToLower(strings.TrimRight(ns, "."))
                        if dsInfo, found := matchDynamicServiceNS(nsLower); found {
                                addDSDetection(detections, dsInfo, zoneCapability(zoneKey))
                        }
                }
        }
        return detections
}

func (a *Analyzer) detectDynamicServices(providers map[string]map[string]any, domain string) {
        if domain == "" {
                return
        }

        zones := map[string]string{
                "_dmarc":     fmt.Sprintf("_dmarc.%s", domain),
                "_domainkey": fmt.Sprintf("_domainkey.%s", domain),
                "_mta-sts":   fmt.Sprintf("_mta-sts.%s", domain),
                "_smtp._tls": fmt.Sprintf("_smtp._tls.%s", domain),
        }

        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()

        detections := a.scanDynamicServiceZones(ctx, zones)

        for _, det := range detections {
                capLabels := strings.Join(det.capabilities, ", ")
                mpi := &managementProviderInfo{
                        Name:         det.info.Name,
                        Vendor:       det.info.Vendor,
                        Capabilities: det.capabilities,
                }
                addOrMergeProvider(providers, mpi, "Dynamic services", fmt.Sprintf("Dynamic services (%s)", capLabels))
        }
}

func identifyEmailProvider(mxRecords []string) string {
        if len(mxRecords) == 0 {
                return ""
        }
        joined := strings.ToLower(strings.Join(mxRecords, " "))
        for pattern, provider := range mxProviderPatterns {
                if strings.Contains(joined, strings.ToLower(pattern)) {
                        return provider
                }
        }
        return ""
}

func identifyDNSProvider(nsRecords []string) string {
        if len(nsRecords) == 0 {
                return ""
        }
        joined := strings.ToLower(strings.Join(nsRecords, " "))
        for pattern, provider := range nsProviderPatterns {
                if strings.Contains(joined, strings.ToLower(pattern)) {
                        return provider
                }
        }
        return ""
}

func identifyWebHosting(basic map[string]any) string {
        if basic == nil {
                return ""
        }
        cnames, _ := basic["CNAME"].([]string)
        joined := strings.ToLower(strings.Join(cnames, " "))

        for pattern, provider := range webHostingPatterns {
                if strings.Contains(joined, pattern) {
                        return provider
                }
        }

        aRecords, _ := basic["A"].([]string)
        if len(aRecords) > 0 {
                if provider := identifyHostingFromPTR(aRecords); provider != "" {
                        return provider
                }
        }

        return ""
}

// lookupAddrFn is the reverse-DNS entrypoint used by identifyHostingFromPTR.
// Production resolves through net.LookupAddr unchanged; tests swap it so the
// default suite never performs live reverse-DNS lookups (which are unbounded —
// net.LookupAddr takes no context — and intermittently overran the analyzer
// quality-gate timeout when fed real IPs on a networked host). Output-neutral:
// the production binding is identical to the prior direct call.
var lookupAddrFn = net.LookupAddr

func identifyHostingFromPTR(aRecords []string) string {
        for _, ip := range aRecords {
                names, err := lookupAddrFn(ip)
                if err != nil || len(names) == 0 {
                        continue
                }
                ptrLower := strings.ToLower(strings.Join(names, " "))
                for pattern, provider := range ptrHostingPatterns {
                        if strings.Contains(ptrLower, pattern) {
                                return provider
                        }
                }
        }
        return ""
}
