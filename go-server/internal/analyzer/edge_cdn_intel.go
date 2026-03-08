//go:build intel

// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// Full intelligence implementation.
package analyzer

import "strings"

const (
        provGoogleCloud    = "Google Cloud"
        provGoogleCloudCDN = "Google Cloud CDN"
        provAmazonCF       = "Amazon CloudFront"
        provAWS            = "Amazon Web Services"
        provLinodeAkamai   = "Linode (Akamai)"
        provAzureCDN       = "Azure CDN"
        provAzureFrontDoor = "Azure Front Door"
        provImperva        = "Imperva (Incapsula)"
)

var cdnASNs = map[string]string{
        "13335":  "Cloudflare",
        "209242": "Cloudflare",
        "20940":  "Akamai",
        "16625":  "Akamai",
        "32787":  "Akamai",
        "54113":  "Fastly",
        "15169":  provGoogleCloudCDN,
        "396982": provGoogleCloud,
        "8075":   "Microsoft Azure CDN",
        "16509":  provAmazonCF,
        "14618":  provAmazonCF,
        "38895":  provAmazonCF,
        "16510":  provAmazonCF,
        "36183":  provAmazonCF,
        "2635":   "Automattic (WordPress.com)",
        "394536": "Sucuri",
        "19551":  "Incapsula (Imperva)",
        "131099": "Cloudflare WARP",
        "46489":  "Twitch (Amazon)",
        "394699": "KeyCDN",
        "30148":  "Sucuri",
        "24940":  "Hetzner",
        "197540": "Netcup",
        "14061":  "DigitalOcean",
        "63949":  provLinodeAkamai,
}

var cloudASNs = map[string]string{
        "16509":  provAWS,
        "14618":  provAWS,
        "8075":   "Microsoft Azure",
        "15169":  provGoogleCloud,
        "396982": provGoogleCloud,
        "14061":  "DigitalOcean",
        "63949":  provLinodeAkamai,
        "24940":  "Hetzner",
        "16276":  "OVHcloud",
        "20473":  "Vultr",
        "13649":  "Rackspace",
        "36351":  "IBM Cloud (SoftLayer)",
        "4808":   "Alibaba Cloud",
        "45102":  "Alibaba Cloud",
        "132203": "Tencent Cloud",
}

var cloudCDNPTRPatterns = map[string]string{
        "cloudfront.net":     provAmazonCF,
        "amazonaws.com":      provAWS,
        "akamaitechnologies": "Akamai",
        "akamaiedge.net":     "Akamai",
        "edgekey.net":        "Akamai",
        "edgesuite.net":      "Akamai",
        "fastly.net":         "Fastly",
        "google.com":         provGoogleCloud,
        "googleusercontent":  provGoogleCloud,
        "1e100.net":          provGoogleCloud,
        "azurewebsites.net":  "Microsoft Azure",
        "azureedge.net":      provAzureCDN,
        "azurefd.net":        provAzureFrontDoor,
        "cloudflare":         "Cloudflare",
        "cdn77.org":          "CDN77",
        "stackpath":          "StackPath",
        "sucuri.net":         "Sucuri",
        "incapdns.net":       provImperva,
        "impervadns.net":     "Imperva",
        "fly.dev":            "Fly.io",
        "render.com":         "Render",
        "netlify.app":        "Netlify",
        "vercel":             "Vercel",
        "heroku":             "Heroku",
        "digitalocean":       "DigitalOcean",
        "linode":             provLinodeAkamai,
        "hetzner":            "Hetzner",
        "ovh.net":            "OVHcloud",
        "vultr.com":          "Vultr",
}

var cdnCNAMEPatterns = map[string]string{
        "cloudfront.net":      provAmazonCF,
        "edgekey.net":         "Akamai",
        "akamaiedge.net":      "Akamai",
        "akadns.net":          "Akamai",
        "edgesuite.net":       "Akamai",
        "akamaized.net":       "Akamai",
        "fastly.net":          "Fastly",
        "cdn.cloudflare.net":  "Cloudflare",
        "cloudflare.net":      "Cloudflare",
        "azureedge.net":       provAzureCDN,
        "azurefd.net":         provAzureFrontDoor,
        "trafficmanager.net":  "Azure Traffic Manager",
        "cdn77.org":           "CDN77",
        "stackpathdns.com":    "StackPath",
        "stackpathcdn.com":    "StackPath",
        "sucuri.net":          "Sucuri",
        "incapdns.net":        provImperva,
        "impervadns.net":      "Imperva",
        "netlify.app":         "Netlify",
        "netlify.com":         "Netlify",
        "vercel-dns.com":      "Vercel",
        "vercel.app":          "Vercel",
        "fly.dev":             "Fly.io",
        "render.com":          "Render",
        "onrender.com":        "Render",
        "pages.dev":           "Cloudflare Pages",
        "workers.dev":         "Cloudflare Workers",
        "herokuapp.com":       "Heroku",
        "heroku.com":          "Heroku",
        "wpengine.com":        "WP Engine",
        "rackcdn.com":         "Rackspace CDN",
        "lxd.io":              "KeyCDN",
        "kxcdn.com":           "KeyCDN",
        "bunnycdn.com":        "BunnyCDN",
        "b-cdn.net":           "BunnyCDN",
}

func DetectEdgeCDN(results map[string]any) map[string]any {
        result := map[string]any{
                "status":         "success",
                "is_behind_cdn":  false,
                "cdn_provider":   "",
                "cdn_indicators": []string{},
                "origin_visible": true,
                "issues":         []string{},
                "message":        "Domain appears to use direct origin hosting",
        }

        var indicators []string
        var provider string

        provider, indicators = checkASNForCDN(results, indicators)

        if provider == "" {
                provider, indicators = checkCNAMEForCDN(results, indicators)
        } else {
                _, indicators = checkCNAMEForCDN(results, indicators)
        }

        ptrProvider, indicators := checkPTRForCDN(results, indicators)
        if provider == "" {
                provider = ptrProvider
        }

        if provider != "" || len(indicators) > 0 {
                result["is_behind_cdn"] = true
                result["cdn_provider"] = provider
                result["cdn_indicators"] = indicators
                result["origin_visible"] = isOriginVisible(provider)
                result["message"] = "Domain is served through " + provider
        }

        return result
}

func checkASNForCDN(results map[string]any, indicators []string) (string, []string) {
        asnData, ok := results["asn_info"].(map[string]any)
        if !ok {
                return "", indicators
        }

        provider, indicators := matchASNEntries(asnData, "ipv4_asn", indicators)
        if provider != "" {
                return provider, indicators
        }

        return matchASNEntries(asnData, "ipv6_asn", indicators)
}

func matchASNEntries(asnData map[string]any, key string, indicators []string) (string, []string) {
        entries, ok := asnData[key].([]map[string]any)
        if !ok {
                return "", indicators
        }

        for _, entry := range entries {
                asn, _ := entry["asn"].(string)
                if asn == "" {
                        continue
                }
                if cdnName, found := cdnASNs[asn]; found {
                        indicators = append(indicators, "ASN "+asn+" is "+cdnName)
                        return cdnName, indicators
                }
        }
        return "", indicators
}

func checkCNAMEForCDN(results map[string]any, indicators []string) (string, []string) {
        basic, ok := results["basic_records"].(map[string]any)
        if !ok {
                return "", indicators
        }

        cnames, _ := basic["CNAME"].([]string)
        for _, cname := range cnames {
                cnameLower := strings.ToLower(cname)
                for pattern, cdnName := range cdnCNAMEPatterns {
                        if strings.Contains(cnameLower, pattern) {
                                indicators = append(indicators, "CNAME points to "+cdnName+" ("+cname+")")
                                return cdnName, indicators
                        }
                }
        }
        return "", indicators
}

func checkPTRForCDN(results map[string]any, indicators []string) (string, []string) {
        basic, ok := results["basic_records"].(map[string]any)
        if !ok {
                return "", indicators
        }

        ptrRecords, _ := basic["PTR"].([]string)
        for _, ptr := range ptrRecords {
                ptrLower := strings.ToLower(ptr)
                for pattern, cdnName := range cloudCDNPTRPatterns {
                        if strings.Contains(ptrLower, pattern) {
                                indicators = append(indicators, "PTR record indicates "+cdnName+" ("+ptr+")")
                                return cdnName, indicators
                        }
                }
        }
        return "", indicators
}

func classifyCloudIP(asn string, ptrRecords []string) (provider string, isCDN bool) {
        if cdnName, found := cdnASNs[asn]; found {
                return cdnName, true
        }

        for _, ptr := range ptrRecords {
                ptrLower := strings.ToLower(ptr)
                for pattern, cdnName := range cloudCDNPTRPatterns {
                        if strings.Contains(ptrLower, pattern) {
                                return cdnName, true
                        }
                }
        }

        if cloudName, found := cloudASNs[asn]; found {
                return cloudName, false
        }

        return "", false
}

func isOriginVisible(provider string) bool {
        hiddenProviders := map[string]bool{
                "Cloudflare":          true,
                "Akamai":              true,
                "Fastly":              true,
                provAzureCDN:           true,
                provAzureFrontDoor:    true,
                "Sucuri":              true,
                provImperva: true,
                "Imperva":             true,
        }
        return !hiddenProviders[provider]
}
