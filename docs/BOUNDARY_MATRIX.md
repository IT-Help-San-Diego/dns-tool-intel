# DNS Tool — Boundary Matrix: Public vs Private Repo Classification

> **Status:** ARCHIVED — Implementation complete (2026-02-17). All action items done.  
> **Canonical version:** Miro Blueprint board `uXjVG83d8PY=`, document A11 (Intel Build Tag Architecture)  
> **Purpose:** Historical design document. Classified every symbol for the two-repo split. The split is now implemented — 11 `_intel.go` files transferred to `careyjames/dns-tool-intel`, OSS build passes cleanly.

> **Generated:** 2026-02-17  
> **Scope:** All 10 stub files + 3 "removed from stub registry" files  
> **Purpose:** Classify every exported/unexported symbol to guide the two-repo split (public `dns-tool-web` vs private `dns-tool-intel`)

---

## Classification Legend

| Tag | Meaning | Rule |
|-----|---------|------|
| **FRAMEWORK** | Belongs in public repo | Type definitions, interfaces, enums, safe empty defaults, utility functions, constants that define the API contract |
| **INTELLIGENCE** | Private repo only | Provider databases, pattern maps, detection algorithms, vendor lists, scoring weights, regex patterns, classification logic |
| **DUAL** | Working code that should be split | Keep a minimal "commodity" version public; move enriched/full version to private |

---

## 1. Summary Table

| # | File | Lines | FRAMEWORK | INTELLIGENCE | DUAL | Notes |
|---|------|------:|----------:|-------------:|-----:|-------|
| 1 | `providers.go` | 144 | 14 | 17 | 3 | Type defs + capability/category constants are framework; vendor names, domain constants, and empty provider maps are intelligence stubs |
| 2 | `infrastructure.go` | 581 | 16 | 23 | 8 | Heavy provider pattern maps (MX, NS, web hosting, PTR) are intelligence; detection functions are dual |
| 3 | `confidence.go` | 54 | 12 | 0 | 0 | Pure framework — all constants and helpers define the confidence contract |
| 4 | `dkim_state.go` | 82 | 10 | 0 | 1 | State machine is framework; `classifyDKIMState` references `protocolState` internals |
| 5 | `ip_investigation.go` | 184 | 16 | 3 | 7 | Types, IP validation, regex are framework; investigation logic and CDN detection stubs are intelligence |
| 6 | `manifest.go` | 29 | 5 | 0 | 0 | Pure framework — type + empty slice + filter function |
| 7 | `ai_surface/http.go` | 10 | 1 | 0 | 0 | Stub HTTP helper — framework |
| 8 | `ai_surface/llms_txt.go` | 27 | 4 | 1 | 0 | Parser stubs are intelligence (detection logic); `CheckLLMSTxt` return shape is framework |
| 9 | `ai_surface/robots_txt.go` | 38 | 4 | 2 | 1 | `knownAICrawlers` is intelligence; `matchAICrawler` is intelligence; `CheckRobotsTxtAI` is dual |
| 10 | `ai_surface/poisoning.go` | 58 | 4 | 4 | 1 | Regex patterns and selectors are intelligence; detection functions are intelligence; `truncate` is framework |
| 11 | `edge_cdn.go` | 265 | 5 | 9 | 3 | ✅ Split — CDN/ASN/CNAME/PTR pattern maps moved to `edge_cdn_intel.go` |
| 12 | `saas_txt.go` | 120 | 4 | 2 | 1 | ✅ Split — SaaS TXT pattern database moved to `saas_txt_intel.go` |
| 13 | `commands.go` | 422 | 28 | 0 | 1 | Pure framework — no action needed |
| 14 | `ai_surface/scanner.go` | 530 | 18 | 1 | 0 | ✅ Split — `aiCrawlers` moved to `scanner_intel.go`, OSS stub returns `[]string{}` |
| **TOTALS** | | **2,544** | **141** | **62** | **26** | |

> All intelligence boundaries are now protected via build tags. No live intelligence data remains in public repo.

---

## 2. Detailed Per-File Classification

### 2.1 `providers.go` (144 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `managementProviderInfo` | type | No | FRAMEWORK | Struct definition — defines the shape of provider data |
| `spfFlatteningInfo` | type | No | FRAMEWORK | Struct definition |
| `hostedDKIMInfo` | type | No | FRAMEWORK | Struct definition |
| `dynamicServiceInfo` | type | No | FRAMEWORK | Struct definition |
| `cnameProviderInfo` | type | No | FRAMEWORK | Struct definition |
| `capDMARCReporting` … `capAIAnalysis` (11 consts) | const | No | FRAMEWORK | Capability string enums — define the vocabulary, not intelligence |
| `catEcommerce` … `catDevOps` (28 consts) | const | No | FRAMEWORK | Category string enums — define the vocabulary |
| `nameOnDMARC` … `nameRedSift` (14 consts) | const | No | INTELLIGENCE | Specific vendor product names — reveals which vendors the tool tracks |
| `vendorRedSift` … `vendorActiveCamp` (14 consts) | const | No | INTELLIGENCE | Vendor identity constants — competitive intelligence |
| `nameAkamai`, `nameSalesforce`, `nameHubSpot`, `nameHeroku` | const | No | DUAL | Well-known names (commodity), but the full list reveals tracking scope |
| `domainOndmarc`, `domainRedsift`, `domainDmarcian`, `domainSendmarc` | const | No | INTELLIGENCE | Provider domain fingerprints — detection intelligence |
| `dmarcMonitoringProviders` | var/map | No | INTELLIGENCE | Empty stub, but key exists — private repo populates with provider DB |
| `spfFlatteningProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `hostedDKIMProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `dynamicServicesProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `dynamicServicesZones` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `cnameProviderMap` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `isHostedEmailProvider` | func | No | DUAL | Stub returns `true` always — needs intelligence to work properly |
| `isBIMICapableProvider` | func | No | DUAL | Stub returns `false` always — needs intelligence |
| `isKnownDKIMProvider` | func | No | DUAL | Stub returns `false` always — needs intelligence |

### 2.2 `infrastructure.go` (581 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `featDDoSProtection` … `detMTASTS` (12 consts) | const | No | FRAMEWORK | Feature label enums |
| `nameGoogleWorkspace` … `nameNamecheap` (8 consts) | const | No | DUAL | Well-known provider names — commodity knowledge, but scope reveals tracking |
| `tierEnterprise`, `tierManaged` | const | No | FRAMEWORK | Tier label enums |
| `providerInfo` | type | No | FRAMEWORK | Struct definition |
| `infraMatch` | type | No | FRAMEWORK | Struct definition |
| `dsDetection` | type | No | FRAMEWORK | Struct definition |
| `enterpriseProviders` | var/map | No | DUAL | **22 entries fully populated** — maps NS patterns to provider info. Contains commodity knowledge (awsdns→Route 53) mixed with competitive intelligence (cscglobal, hetzner, vultr patterns) |
| `legacyProviderBlocklist` | var/map | No | INTELLIGENCE | List of legacy/deprecated providers — proprietary assessment |
| `selfHostedEnterprise` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `governmentDomains` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `managedProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `hostingProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `hostingPTRProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `dnsHostingProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `emailHostingProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `hostedMXProviders` | var/map | No | INTELLIGENCE | Empty stub — private repo populates |
| `AnalyzeDNSInfrastructure` | method | Yes | DUAL | Working implementation with `matchEnterpriseProvider` — commodity logic using the `enterpriseProviders` map |
| `GetHostingInfo` | method | Yes | DUAL | Working implementation calling identification functions |
| `DetectEmailSecurityManagement` | method | Yes | FRAMEWORK | Stub returning empty defaults — framework shape |
| `enrichHostingFromEdgeCDN` | func | No | FRAMEWORK | Empty stub |
| `matchEnterpriseProvider` | func | No | DUAL | **Fully implemented** — iterates `enterpriseProviders` and `legacyProviderBlocklist` |
| `matchSelfHostedProvider` | func | No | INTELLIGENCE | Stub returns nil — private repo implements |
| `matchManagedProvider` | func | No | INTELLIGENCE | Stub returns nil |
| `matchGovernmentDomain` | func | No | INTELLIGENCE | Stub returns nil, false |
| `collectAltSecurityItems` | func | No | INTELLIGENCE | Stub returns nil |
| `assessTier` | func | No | INTELLIGENCE | Stub returns "Standard DNS" |
| `resolveNSRecords` | method | No | FRAMEWORK | Pass-through stub |
| `matchAllProviders` | func | No | INTELLIGENCE | Stub returns nil |
| `buildInfraResult` | func | No | INTELLIGENCE | Stub returns empty map |
| `parentZone` | func | No | FRAMEWORK | Pure utility — string splitting |
| `detectHostingFromPTR` | method | No | INTELLIGENCE | Stub returns empty |
| `resolveDNSHosting` | method | No | INTELLIGENCE | Stub returns empty |
| `resolveEmailHosting` | func | No | INTELLIGENCE | Stub returns empty |
| `applyHostingDefaults` | func | No | FRAMEWORK | Pure utility — default value assignment |
| `hostingConfidence` | func | No | FRAMEWORK | Stub returns empty map |
| `dnsConfidence` | func | No | FRAMEWORK | Stub returns empty map |
| `emailConfidence` | func | No | FRAMEWORK | Stub returns empty map |
| `detectEmailProviderFromSPF` | func | No | INTELLIGENCE | Stub returns empty |
| `detectProvider` | func | No | INTELLIGENCE | Stub returns empty |
| `extractMailtoDomains` | func | No | FRAMEWORK | Stub returns nil — utility |
| `matchMonitoringProvider` | func | No | INTELLIGENCE | Stub returns nil |
| `addOrMergeProvider` | func | No | FRAMEWORK | Empty stub — merge utility |
| `containsStr` | func | No | FRAMEWORK | Pure utility — slice search |
| `detectDMARCReportProviders` | func | No | INTELLIGENCE | Empty stub |
| `detectTLSRPTReportProviders` | func | No | INTELLIGENCE | Empty stub |
| `detectSPFFlatteningProvider` | func | No | INTELLIGENCE | Stub returns nil |
| `detectMTASTSManagement` | func | No | INTELLIGENCE | Empty stub |
| `detectHostedDKIMProviders` | method | No | INTELLIGENCE | Empty stub |
| `zoneCapability` | func | No | FRAMEWORK | Simple string concatenation |
| `matchDynamicServiceNS` | func | No | INTELLIGENCE | Stub returns false |
| `addDSDetection` | func | No | FRAMEWORK | Empty stub — utility |
| `scanDynamicServiceZones` | method | No | INTELLIGENCE | Stub returns empty map |
| `detectDynamicServices` | func | No | INTELLIGENCE | Empty stub |
| `mxProviderPatterns` | var/map | No | DUAL | **28 entries fully populated** — maps MX hostname patterns to email providers |
| `identifyEmailProvider` | func | No | DUAL | **Fully implemented** — iterates `mxProviderPatterns` |
| `nsProviderPatterns` | var/map | No | DUAL | **24 entries fully populated** — maps NS patterns to DNS providers |
| `identifyDNSProvider` | func | No | DUAL | **Fully implemented** — iterates `nsProviderPatterns` |
| `webHostingPatterns` | var/map | No | DUAL | **22 entries fully populated** — maps CNAME patterns to hosting providers |
| `ptrHostingPatterns` | var/map | No | INTELLIGENCE | **14 entries fully populated** — PTR-based hosting detection |
| `identifyWebHosting` | func | No | DUAL | **Fully implemented** — uses `webHostingPatterns` + PTR fallback |
| `identifyHostingFromPTR` | func | No | INTELLIGENCE | **Fully implemented** — iterates `ptrHostingPatterns` with `net.LookupAddr` |

### 2.3 `confidence.go` (54 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `ConfidenceObserved` | const | Yes | FRAMEWORK | Confidence level enum |
| `ConfidenceInferred` | const | Yes | FRAMEWORK | Confidence level enum |
| `ConfidenceThirdParty` | const | Yes | FRAMEWORK | Confidence level enum |
| `ConfidenceLabelObserved` | const | Yes | FRAMEWORK | Display label |
| `ConfidenceLabelInferred` | const | Yes | FRAMEWORK | Display label |
| `ConfidenceLabelThirdParty` | const | Yes | FRAMEWORK | Display label |
| `MethodDNSRecord` … `MethodPTRRecord` (18 consts) | const | Yes | FRAMEWORK | Detection method enums — define the vocabulary of evidence sources |
| `confidenceMap` | func | No | FRAMEWORK | Helper — builds confidence map from level/label/method |
| `ConfidenceObservedMap` | func | Yes | FRAMEWORK | Factory function |
| `ConfidenceInferredMap` | func | Yes | FRAMEWORK | Factory function |
| `ConfidenceThirdPartyMap` | func | Yes | FRAMEWORK | Factory function |

### 2.4 `dkim_state.go` (82 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `DKIMState` | type | Yes | FRAMEWORK | Enum type definition |
| `DKIMAbsent` … `DKIMNoMailDomain` (7 consts) | const | Yes | FRAMEWORK | State enum values |
| `DKIMState.String` | method | Yes | FRAMEWORK | Stringer — maps enum to string |
| `DKIMState.IsPresent` | method | Yes | FRAMEWORK | Boolean predicate on enum |
| `DKIMState.IsConfigured` | method | Yes | FRAMEWORK | Boolean predicate on enum |
| `DKIMState.NeedsAction` | method | Yes | FRAMEWORK | Boolean predicate on enum |
| `DKIMState.NeedsMonitoring` | method | Yes | FRAMEWORK | Boolean predicate on enum |
| `classifyDKIMState` | func | No | DUAL | Classification logic using `protocolState` fields — the decision tree itself is intelligence, but the mapping from boolean flags to states is relatively obvious |

### 2.5 `ip_investigation.go` (184 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `IPRelationship` | type | Yes | FRAMEWORK | Struct with JSON tags — API contract |
| `ipv4Re`, `ipv6Re` | var | No | FRAMEWORK | Standard IP regex — not proprietary |
| `spfIPv4Re`, `spfIPv6Re` | var | No | FRAMEWORK | SPF extraction regex — RFC-defined format |
| `neighborhoodDisplayCap` | const | No | FRAMEWORK | Display constant |
| `classCDNEdge` … `classCTSubdomain` (9 consts) | const | No | FRAMEWORK | Classification label enums |
| `ValidateIPAddress` | func | Yes | FRAMEWORK | Uses `net.ParseIP` — standard library |
| `IsPrivateIP` | func | Yes | FRAMEWORK | Standard RFC 1918/etc checks |
| `IsIPv6` | func | Yes | FRAMEWORK | Simple string check |
| `InvestigateIP` | method | Yes | DUAL | Returns stub defaults — framework shape, but full implementation is intelligence |
| `buildArpaName` | func | No | FRAMEWORK | Standard ARPA name construction |
| `fetchNeighborhoodDomains` | func | No | INTELLIGENCE | Stub — neighborhood analysis is intelligence |
| `buildNeighborhoodContext` | func | No | INTELLIGENCE | Stub — contextual analysis |
| `buildExecutiveVerdict` | func | No | INTELLIGENCE | Stub — verdict generation is high-value intelligence |
| `findFirstHostname` | func | No | FRAMEWORK | Utility — searches slice for match |
| `verdictSeverity` | func | No | DUAL | Stub returns "info" — severity mapping logic is intelligence |
| `checkPTRRecords` | method | No | DUAL | Pass-through stub — implementation is intelligence |
| `checkDomainARecords` | method | No | DUAL | Pass-through stub |
| `checkMXRecords` | method | No | DUAL | Pass-through stub |
| `checkNSRecords` | method | No | DUAL | Pass-through stub |
| `checkSPFAuthorization` | method | No | DUAL | Pass-through stub |
| `findSPFTXTRecord` | func | No | FRAMEWORK | Utility — finds SPF in TXT records |
| `checkSPFIncludes` | method | No | DUAL | Pass-through stub |
| `checkIPInSPFRecord` | func | No | FRAMEWORK | RFC-defined SPF parsing (stub) |
| `checkCTSubdomains` | method | No | INTELLIGENCE | Stub — CT log analysis |
| `lookupInvestigationASN` | method | No | INTELLIGENCE | Stub — ASN enrichment |
| `checkASNForCDNDirect` | func | No | INTELLIGENCE | Stub — CDN detection from ASN |
| `extractMXHost` | func | No | FRAMEWORK | String utility |
| `classifyOverall` | func | No | INTELLIGENCE | Stub — overall classification logic |
| `mapGetStr` | func | No | FRAMEWORK | Map accessor utility |

### 2.6 `manifest.go` (29 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `ManifestEntry` | type | Yes | FRAMEWORK | Struct definition — feature manifest schema |
| `FeatureParityManifest` | var | Yes | FRAMEWORK | Empty slice — populated by private repo at build |
| `RequiredSchemaKeys` | var | Yes | FRAMEWORK | Empty slice — populated by private repo |
| `init` | func | No | FRAMEWORK | Empty init — placeholder for private build injection |
| `GetManifestByCategory` | func | Yes | FRAMEWORK | Filter utility over manifest slice |

### 2.7 `ai_surface/http.go` (10 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `Scanner.fetchTextFile` | method | No | FRAMEWORK | HTTP utility stub — generic fetcher |

### 2.8 `ai_surface/llms_txt.go` (27 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `Scanner.CheckLLMSTxt` | method | Yes | FRAMEWORK | Returns default shape — contract definition |
| `looksLikeLLMSTxt` | func | No | INTELLIGENCE | Detection heuristic (stub) |
| `parseLLMSTxt` | func | No | INTELLIGENCE | Parsing logic (stub) |
| `parseLLMSTxtFieldLine` | func | No | FRAMEWORK | Field-level parser utility (stub) |

### 2.9 `ai_surface/robots_txt.go` (38 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `knownAICrawlers` | var | No | INTELLIGENCE | **Empty in stub**, but scanner.go exposes `aiCrawlers` with 15 crawler names |
| `robotsDirective` | type | No | FRAMEWORK | Struct definition — JSON schema |
| `Scanner.CheckRobotsTxtAI` | method | Yes | DUAL | Returns default shape (framework), but full implementation needs crawler list |
| `parseRobotsForAI` | func | No | INTELLIGENCE | Parsing + classification logic (stub) |
| `processRobotsLine` | func | No | FRAMEWORK | Line-level parser utility (stub) |
| `matchAICrawler` | func | No | INTELLIGENCE | Crawler matching logic (stub) |

### 2.10 `ai_surface/poisoning.go` (58 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `prefilledPromptRe` | var | No | INTELLIGENCE | Placeholder regex — real patterns are intelligence |
| `promptInjectionRe` | var | No | INTELLIGENCE | Placeholder regex — real patterns are intelligence |
| `hiddenTextSelectors` | var | No | INTELLIGENCE | Empty slice — CSS/HTML selectors for hidden text detection |
| `Scanner.DetectPoisoningIOCs` | method | Yes | FRAMEWORK | Returns default shape — contract |
| `truncate` | func | No | FRAMEWORK | Pure utility |
| `Scanner.DetectHiddenPrompts` | method | Yes | FRAMEWORK | Returns default shape — contract |
| `detectHiddenTextArtifacts` | func | No | INTELLIGENCE | Detection logic (stub) |
| `buildHiddenBlockRegex` | func | No | INTELLIGENCE | Regex construction (stub) |
| `extractTextContent` | func | No | FRAMEWORK | HTML text extraction utility (stub) |
| `looksLikePromptInstruction` | func | No | INTELLIGENCE | Classification heuristic (stub) |

### 2.11 `edge_cdn.go` ⚠️ NOT STUBBED (265 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `cdnASNs` | var/map | No | **INTELLIGENCE** | **⚠️ EXPOSED: 22 ASN→CDN mappings fully populated** |
| `cloudASNs` | var/map | No | **INTELLIGENCE** | **⚠️ EXPOSED: 15 ASN→cloud provider mappings** |
| `cloudCDNPTRPatterns` | var/map | No | **INTELLIGENCE** | **⚠️ EXPOSED: 30 PTR pattern→provider mappings** |
| `cdnCNAMEPatterns` | var/map | No | **INTELLIGENCE** | **⚠️ EXPOSED: 36 CNAME pattern→CDN mappings** |
| `DetectEdgeCDN` | func | Yes | DUAL | **⚠️ EXPOSED: Full working CDN detection algorithm** |
| `checkASNForCDN` | func | No | DUAL | **⚠️ EXPOSED: Full working ASN→CDN logic** |
| `matchASNEntries` | func | No | DUAL | **⚠️ EXPOSED: Full working ASN matching** |
| `checkCNAMEForCDN` | func | No | DUAL | **⚠️ EXPOSED: Full working CNAME→CDN logic** |
| `checkPTRForCDN` | func | No | INTELLIGENCE | **⚠️ EXPOSED: Full working PTR→CDN logic** |
| `classifyCloudIP` | func | No | INTELLIGENCE | **⚠️ EXPOSED: Full cloud IP classification** |
| `isOriginVisible` | func | No | INTELLIGENCE | **⚠️ EXPOSED: 8-entry hidden-origin provider list** |

### 2.12 `saas_txt.go` ⚠️ NOT STUBBED (120 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `saasPattern` | type | No | FRAMEWORK | Struct definition |
| `saasPatterns` | var/slice | No | **INTELLIGENCE** | **⚠️ EXPOSED: 48 SaaS TXT verification regex patterns** |
| `ExtractSaaSTXTFootprint` | func | Yes | DUAL | **⚠️ EXPOSED: Full SaaS footprint extraction algorithm** |
| `matchSaaSPatterns` | func | No | INTELLIGENCE | **⚠️ EXPOSED: Pattern matching logic** |
| `truncateRecord` | func | No | FRAMEWORK | Pure utility |

### 2.13 `commands.go` ⚠️ NOT STUBBED (422 lines)

| Symbol | Kind | Exported | Classification | Reasoning |
|--------|------|----------|---------------|-----------|
| `sectionDNSRecords` … `sectionAISurface` (7 consts) | const | No | FRAMEWORK | Section label enums |
| `rfcDNS1035` … `rfcCDS7344` (14 consts) | const | No | FRAMEWORK | RFC reference constants |
| `VerifyCommand` | type | Yes | FRAMEWORK | Struct definition — command schema |
| `GenerateVerificationCommands` | func | Yes | FRAMEWORK | Orchestrator — calls sub-generators |
| `generateDNSRecordCommands` | func | No | FRAMEWORK | Generates standard `dig` commands |
| `generateSPFCommands` | func | No | FRAMEWORK | Standard SPF check command |
| `generateDMARCCommands` | func | No | FRAMEWORK | Standard DMARC check command |
| `generateDKIMCommands` | func | No | FRAMEWORK | Standard DKIM check commands |
| `generateDNSSECCommands` | func | No | FRAMEWORK | Standard DNSSEC check commands |
| `generateDANECommands` | func | No | FRAMEWORK | Standard DANE/TLSA check commands |
| `generateMTASTSCommands` | func | No | FRAMEWORK | Standard MTA-STS check commands |
| `generateTLSRPTCommands` | func | No | FRAMEWORK | Standard TLS-RPT check command |
| `generateBIMICommands` | func | No | FRAMEWORK | Standard BIMI check command |
| `generateCAACommands` | func | No | FRAMEWORK | Standard CAA check command |
| `generateHTTPSSVCBCommands` | func | No | FRAMEWORK | Standard HTTPS/SVCB check command |
| `generateCDSCommands` | func | No | FRAMEWORK | Standard CDS check command |
| `generateRegistrarCommands` | func | No | FRAMEWORK | Standard RDAP lookup command |
| `generateSMTPCommands` | func | No | FRAMEWORK | Standard SMTP STARTTLS check |
| `generateCTCommands` | func | No | FRAMEWORK | Standard CT log search command |
| `generateDMARCReportAuthCommands` | func | No | FRAMEWORK | Standard DMARC ext-report check |
| `generateASNCommands` | func | No | FRAMEWORK | Standard Team Cymru ASN lookup |
| `generateAISurfaceCommands` | func | No | FRAMEWORK | Standard AI surface check commands |
| `generateSecurityTxtCommands` | func | No | FRAMEWORK | Standard security.txt check |
| `extractMXHostsFromResults` | func | No | FRAMEWORK | Result extraction utility |
| `parseMXHostEntries` | func | No | FRAMEWORK | MX parsing utility |
| `appendMXHost` | func | No | FRAMEWORK | Append utility |
| `extractDKIMSelectors` | func | No | DUAL | Extracts selectors from result — has working logic that knows DKIM structure |
| `extractDMARCRuaTargets` | func | No | FRAMEWORK | Result extraction utility |
| `extractIPsFromResults` | func | No | FRAMEWORK | Result extraction utility |
| `reverseIP` | func | No | FRAMEWORK | Pure utility — IP octet reversal |

---

## 3. Intelligence Exposure Audit

The following competitive intelligence is currently **fully exposed** in the public repository:

### 🔴 Critical Exposures (files not stubbed at all)

#### `edge_cdn.go` — Full CDN/Cloud Detection Database
- **`cdnASNs`**: 22 ASN-to-CDN-provider mappings (Cloudflare, Akamai, Fastly, Google, Microsoft, Amazon, Automattic, Sucuri, Imperva, KeyCDN, Hetzner, DigitalOcean, Linode, etc.)
- **`cloudASNs`**: 15 ASN-to-cloud-provider mappings (AWS, Azure, GCP, DigitalOcean, Vultr, OVH, Alibaba, Tencent, IBM, Rackspace)
- **`cloudCDNPTRPatterns`**: 30 PTR hostname patterns for reverse-DNS cloud/CDN detection
- **`cdnCNAMEPatterns`**: 36 CNAME-to-CDN mappings including edge-specific domains (edgekey.net, akamaiedge.net, azurefd.net, etc.)
- **`isOriginVisible`**: Which CDN providers hide origin IPs (Cloudflare, Akamai, Fastly, Sucuri, Imperva, Azure CDN/FD)
- **Full detection algorithms**: `DetectEdgeCDN`, `checkASNForCDN`, `checkCNAMEForCDN`, `checkPTRForCDN`, `classifyCloudIP`

#### `saas_txt.go` — Full SaaS TXT Verification Database
- **`saasPatterns`**: 48 compiled regex patterns covering Google, Facebook, Apple, Microsoft, OpenAI, Adobe, Atlassian, DocuSign, Dropbox, GitHub, GitLab, HubSpot, LinkedIn, Notion, Pinterest, Salesforce, Slack, Stripe, Twilio, Twitter/X, Zoom, Webex, Citrix, Canva, Shopify, Zendesk, 1Password, Amazon SES, Brevo, Mailchimp, Miro, Intercom, Statuspage, Smartsheet, HIBP, Cisco Umbrella, Detectify, Dynatrace, MongoDB, Fastly, Ahrefs, Brave, Sophos
- **Full extraction algorithm**: `ExtractSaaSTXTFootprint`, `matchSaaSPatterns`

### 🟡 Moderate Exposures (in stub files but with populated maps)

#### `infrastructure.go` — Provider Identification Databases
- **`enterpriseProviders`**: 22 NS-pattern-to-provider entries with tier + feature metadata (Route 53, Cloudflare, Azure DNS, UltraDNS, Oracle Dyn, NS1, Google Cloud DNS, CSC Global, Akamai, GoDaddy, Namecheap, Hurricane Electric, Hetzner, DigitalOcean, Vultr, DNSimple, Netlify, Vercel)
- **`legacyProviderBlocklist`**: 10 legacy/deprecated providers (Network Solutions, Worldnic, Bluehost, HostGator, iPage, FatCow, JustHost, HostMonster, Arvixe, Site5)
- **`mxProviderPatterns`**: 28 MX-to-email-provider mappings
- **`nsProviderPatterns`**: 24 NS-to-DNS-provider mappings
- **`webHostingPatterns`**: 22 CNAME-to-hosting mappings
- **`ptrHostingPatterns`**: 14 PTR-to-hosting mappings
- **Working detection functions**: `identifyEmailProvider`, `identifyDNSProvider`, `identifyWebHosting`, `identifyHostingFromPTR`, `matchEnterpriseProvider`

#### `providers.go` — Vendor Identity Database
- 14 DMARC/email security vendor names (OnDMARC, DMARCLY, Dmarcian, Sendmarc, Proofpoint, Valimail, PowerDMARC, Mailhardener, Fraudmarc, EasyDMARC, DMARC Advisor, Agari, Red Sift)
- 14 vendor identity constants
- 4 provider domain fingerprints (ondmarc.com, redsift.cloud, dmarcian.com, sendmarc.com)

### ✅ Resolved: `ai_surface/scanner.go` — Now Split (2026-02-17)

The `aiCrawlers` list (15 AI crawler names) has been extracted into the three-file pattern:
- **`scanner.go`** — Framework orchestration (`Scanner`, `Scan`, `parseRobotsTxtForAI` calls `GetAICrawlers()`)
- **`scanner_oss.go`** — `//go:build !intel` — Returns empty `[]string{}` (no crawler intelligence in OSS)
- **`scanner_intel.go`** — `//go:build intel` — Full 15-crawler list (private repo only)

Remaining framework-level patterns in `scanner.go` (not intelligence — general heuristics):
- **`prefillPatterns`** in `scanForPrefillLinks`: 5 AI chat prefill URL patterns
- **`hiddenPatterns`** in `scanForHiddenPrompts`: 4 CSS/HTML hiding techniques
- **`promptKeywords`** in `scanForHiddenPrompts`: 6 prompt injection keywords

---

## 4. Commodity Allowance

The following minimal intelligence can safely remain in the public repo for demo/open-source fidelity, as it represents widely-known, easily-discoverable information:

### ✅ Safe to Keep Public (Commodity Knowledge)

| Category | What | Reasoning |
|----------|------|-----------|
| **Email Provider from MX** | Google Workspace (`google`, `googlemail`, `gmail`), Microsoft 365 (`outlook`, `protection.outlook`), Proton Mail (`protonmail`) | Any admin can identify these from MX records; documented in provider setup guides |
| **DNS Provider from NS** | Cloudflare (`cloudflare`), Route 53 (`awsdns`, `route53`), Google Cloud DNS (`google`), Azure DNS (`azure-dns`) | NS records are public and self-identifying |
| **Major CDN from CNAME** | CloudFront (`cloudfront.net`), Cloudflare (`cloudflare.net`), Fastly (`fastly.net`) | CNAME targets are public DNS records |
| **Web Hosting from CNAME** | Netlify, Vercel, Heroku, GitHub Pages, Shopify | Well-known CNAME patterns from their docs |
| **Confidence framework** | All of `confidence.go` | Defines evidence vocabulary, not detection logic |
| **DKIM state machine** | All of `dkim_state.go` | State transitions are public RFC semantics |
| **Manifest structure** | All of `manifest.go` | Schema definitions with no intelligence |
| **Verification commands** | All of `commands.go` | Standard `dig`/`curl`/`openssl` one-liners |
| **SaaS TXT (top 5 only)** | Google, Facebook, Microsoft, Apple, OpenAI | Well-documented domain verification patterns |
| **AI Crawlers (top 3)** | GPTBot, Google-Extended, CCBot | Widely published in robots.txt guides |

### 🔒 Must Move to Private

| Category | What | Why |
|----------|------|-----|
| **DMARC vendor database** | 14 monitoring provider names + domain fingerprints | Reveals competitive landscape tracking scope |
| **Enterprise NS provider map (full)** | Beyond top 5 → CSC Global, UltraDNS, Oracle Dyn, NS1, etc. | Niche provider identification is competitive advantage |
| **Legacy provider blocklist** | 10 deprecated providers | Proprietary quality assessment |
| **Full MX provider map** | Beyond Google/Microsoft → Barracuda, Sophos, Forcepoint, Hornetsecurity, etc. | Security email gateway identification |
| **Full CDN ASN database** | `cdnASNs`, `cloudASNs` | ASN-to-provider mapping at this scale is proprietary enrichment |
| **PTR hosting patterns** | All 14 PTR-based identifications | Reverse-DNS fingerprinting technique |
| **Full SaaS TXT patterns** | Beyond top 5 → 43 patterns covering security, HR, collaboration tools | SaaS footprint intelligence reveals tracking depth |
| **AI poisoning detection** | `prefilledPromptRe`, `promptInjectionRe`, hidden text selectors | Novel detection methodology |
| **AI crawler full list** | Beyond top 3 → 12 additional crawlers | Comprehensive crawler tracking |
| **CDN CNAME patterns (full)** | Beyond top 3 → 33 additional CDN edge domains | Edge-domain fingerprinting database |

### 📋 Recommended Commodity Stub Sizes

| Map | Current Size | Commodity Allowance | Private Enrichment |
|-----|-------------|--------------------|--------------------|
| `enterpriseProviders` | 22 entries | 5 (AWS, Cloudflare, Azure, Google, GoDaddy) | +17 |
| `mxProviderPatterns` | 28 entries | 3 (Google, Microsoft, Zoho) | +25 |
| `nsProviderPatterns` | 24 entries | 4 (Cloudflare, Route 53, Google, Azure) | +20 |
| `webHostingPatterns` | 22 entries | 5 (Cloudflare, AWS, Netlify, Vercel, Heroku) | +17 |
| `ptrHostingPatterns` | 14 entries | 0 (entire technique is intelligence) | +14 |
| `cdnASNs` | 22 entries | 3 (Cloudflare, Akamai, Fastly) | +19 |
| `cloudASNs` | 15 entries | 3 (AWS, Azure, GCP) | +12 |
| `cdnCNAMEPatterns` | 36 entries | 3 (cloudfront.net, cloudflare.net, fastly.net) | +33 |
| `cloudCDNPTRPatterns` | 30 entries | 0 (entire technique is intelligence) | +30 |
| `saasPatterns` | 48 entries | 5 (Google, Facebook, Microsoft, Apple, OpenAI) | +43 |
| `aiCrawlers` | 15 entries | 3 (GPTBot, Google-Extended, CCBot) | +12 |

---

## 5. Action Items

1. ~~**Immediate**: Stub `edge_cdn.go` and `saas_txt.go`~~ ✅ DONE (2026-02-17) — Split into three-file pattern
2. ~~**Immediate**: Move `scanner.go`'s `aiCrawlers` to private~~ ✅ DONE (2026-02-17) — Split into `scanner.go` + `scanner_oss.go` + `scanner_intel.go`
3. **Low Priority**: `prefillPatterns`, `hiddenPatterns`, `promptKeywords` in `scanner.go` are framework-level heuristics, not proprietary intelligence — no action needed
4. **Low Priority**: `commands.go` is safe as-is (pure framework) — no action needed
5. **Low Priority**: `confidence.go`, `dkim_state.go`, `manifest.go` are pure framework — no action needed

### Intel Transfer Status (2026-02-17)
- ✅ All 11 `_intel.go` files transferred to `careyjames/dns-tool-intel` private repo
- ✅ `docs/intel-staging/` deleted from public repo
- ✅ OSS build (`go build ./go-server/cmd/server/`) passes cleanly
