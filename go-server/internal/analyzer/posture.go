// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
	"fmt"
	"strings"
)

const (
	riskLow      = "Low Risk"
	riskMedium   = "Medium Risk"
	riskHigh     = "High Risk"
	riskCritical = "Critical Risk"

	iconShieldAlt           = "shield-alt"
	iconExclamationTriangle = "exclamation-triangle"

	protocolMTASTS = "MTA-STS"
	protocolTLSRPT = "TLS-RPT"

	mapKeyAiCrawlerGovernance = "ai_crawler_governance"
	mapKeyAiLlmsTxt           = "ai_llms_txt"
	mapKeyAnswer              = "answer"
	mapKeyBrandImpersonation  = "brand_impersonation"
	mapKeyColor               = "color"
	mapKeyDanger              = "danger"
	mapKeyDnsTampering        = "dns_tampering"
	mapKeyEmailSpoofing       = "email_spoofing"
	mapKeySecondary           = "secondary"
	mapKeyTransport           = "transport"
	strBasic                  = "Basic"
	strExposed                = "Exposed"
	strLikely                 = "Likely"
	strPartially              = "Partially"
	strPossible               = "Possible"
	strProtected              = "Protected"
	strQuarantined            = "Quarantined"
	strPartly                 = "Partly"
	strUnlikely               = "Unlikely"
	mapKeyIcon                = "icon"
	mapKeyLabel               = "label"
	answerYes                 = "Yes"
	statusNone                = "none"
	statusInfoPosture         = "info"
)

type protocolState struct {
	spfOK               bool
	spfWarning          bool
	spfMissing          bool
	spfIndeterminate    bool
	spfHardFail         bool
	spfDangerous        bool
	spfNeutral          bool
	spfLookupExceeded   bool
	spfLookupCount      int
	dmarcOK             bool
	dmarcWarning        bool
	dmarcMissing        bool
	dmarcIndeterminate  bool
	dmarcPolicy         string
	dmarcPct            int
	dmarcHasRua         bool
	dmarcHasRuf         bool
	dmarcStrictAlign    bool
	dkimOK              bool
	dkimProvider        bool
	dkimPartial         bool
	dkimWeakKeys        bool
	dkimThirdPartyOnly  bool
	caaOK               bool
	mtaStsOK            bool
	tlsrptOK            bool
	bimiOK              bool
	caaIndeterminate    bool
	mtaStsIndeterminate bool
	tlsrptIndeterminate bool
	bimiIndeterminate   bool
	daneOK              bool
	daneIndeterminate   bool
	daneProviderLimited bool
	dnssecOK            bool
	dnssecBroken        bool
	dnssecIndeterminate bool
	dnssecADValidated   bool
	dnssecAlgoStrength  string
	primaryProvider     string
	isNoMailDomain      bool
	probableNoMail      bool
	isTLD               bool
}

type postureAccumulator struct {
	issues          []string
	recommendations []string
	monitoring      []string
	configured      []string
	absent          []string
	providerLimited []string
}

type gradeInput struct {
	corePresent           bool
	dmarcFullEnforcing    bool
	dmarcPartialEnforcing bool
	dmarcStrict           bool
	hasCAA                bool
	hasSPF                bool
	hasDMARC              bool
	hasDKIM               bool
	dkimInconclusive      bool
	isNoMail              bool
	monitoring            []string
	configured            []string
	absent                []string
}

func evaluateSPFState(spf map[string]any) (spfOK, spfWarning, spfMissing, spfHardFail, spfDangerous, spfNeutral, spfLookupExceeded bool, spfLookupCount int) {
	if isMissingRecord(spf) {
		spfMissing = true
		return
	}

	status, _ := spf[mapKeyStatus].(string)
	switch status {
	case mapKeySuccess:
		spfOK = true
	case mapKeyWarning:
		spfWarning = true
		spfOK = true
	case statusIndeterminate:
		// Transient lookup failure — neither configured nor absent. Exclude
		// from the posture verdict entirely (parity with DNSSEC, whose switch
		// already leaves indeterminate as neither OK nor broken) so a SERVFAIL
		// is never scored as a missing record.
		return
	default:
		spfMissing = true
	}

	mechanism, _ := spf["all_mechanism"].(string)
	mechanism = strings.TrimSpace(mechanism)
	switch mechanism {
	case "-all":
		spfHardFail = true
	case "+all":
		spfDangerous = true
	case "?all":
		spfNeutral = true
	}

	spfLookupCount = extractIntField(spf, "lookup_count")
	if spfLookupCount > 10 {
		spfLookupExceeded = true
	}
	return
}

// dmarcReportingSignals reads the tags the deliberateness model needs and that
// the analyzer already parses but previously threw away at this boundary: ruf=
// (forensic reporting) and strict alignment. ruf= is the single strongest
// collection tell — DMARCbis removed it and the large receivers ignore it, so
// publishing it in 2026 is a choice, not an inherited default.
func dmarcReportingSignals(dmarc map[string]any) (hasRuf, strictAlign bool) {
	if ruf, ok := dmarc["ruf"].(string); ok && ruf != "" {
		hasRuf = true
	}
	aspf, _ := dmarc["aspf"].(string)
	adkim, _ := dmarc["adkim"].(string)
	strictAlign = aspf == "strict" && adkim == "strict"
	return
}

func evaluateDMARCState(dmarc map[string]any) (dmarcOK, dmarcWarning, dmarcMissing, dmarcHasRua bool, dmarcPolicy string, dmarcPct int) {
	if isMissingRecord(dmarc) {
		dmarcMissing = true
		return
	}

	status, _ := dmarc[mapKeyStatus].(string)
	switch status {
	case mapKeySuccess:
		dmarcOK = true
	case mapKeyWarning:
		dmarcWarning = true
		dmarcOK = true
	case statusIndeterminate:
		// Transient lookup failure — neither configured nor absent. Exclude
		// from the posture verdict entirely (parity with DNSSEC) so a SERVFAIL
		// is never scored as a missing record.
		return
	default:
		dmarcMissing = true
	}

	dmarcPolicy, _ = dmarc["policy"].(string)
	dmarcPct = extractIntFieldDefault(dmarc, "pct", 100)
	if rua, ok := dmarc["rua"].(string); ok && rua != "" {
		dmarcHasRua = true
	}
	return
}

func evaluateDKIMState(dkim map[string]any) (dkimOK, dkimProvider, dkimPartial, dkimWeakKeys, dkimThirdPartyOnly bool, primaryProvider string) {
	if isMissingRecord(dkim) {
		return
	}

	status, _ := dkim[mapKeyStatus].(string)
	switch status {
	case mapKeySuccess:
		dkimOK = true
	case mapKeyWarning:
		dkimOK = true
	}

	if pp, ok := dkim["primary_provider"].(string); ok && pp != "" {
		primaryProvider = pp
		dkimProvider = true
	}

	dkimWeakKeys, dkimThirdPartyOnly = evaluateDKIMIssues(dkim)

	recordsFound := extractIntField(dkim, "records_found")
	if recordsFound > 0 && !dkimOK {
		dkimPartial = true
	}
	return
}

func evaluateSimpleProtocolState(analysis map[string]any, successField string) bool {
	if isMissingRecord(analysis) {
		return false
	}
	status, _ := analysis[successField].(string)
	return status == mapKeySuccess
}

func evaluateProtocolStates(results map[string]any) protocolState {
	ps := protocolState{}

	spf, _ := results["spf_analysis"].(map[string]any)
	dmarc, _ := results["dmarc_analysis"].(map[string]any)
	dkim, _ := results["dkim_analysis"].(map[string]any)
	mtaSts, _ := results["mta_sts_analysis"].(map[string]any)
	tlsrpt, _ := results["tlsrpt_analysis"].(map[string]any)
	bimi, _ := results["bimi_analysis"].(map[string]any)
	dane, _ := results["dane_analysis"].(map[string]any)
	caa, _ := results["caa_analysis"].(map[string]any)
	dnssec, _ := results["dnssec_analysis"].(map[string]any)

	if nullMX, ok := results["has_null_mx"].(bool); ok {
		ps.isNoMailDomain = nullMX
	}
	if noMail, ok := results["is_no_mail_domain"].(bool); ok && noMail {
		ps.isNoMailDomain = true
	}
	if !ps.isNoMailDomain {
		ps.probableNoMail = detectProbableNoMail(results)
	}

	ps.spfOK, ps.spfWarning, ps.spfMissing, ps.spfHardFail, ps.spfDangerous, ps.spfNeutral, ps.spfLookupExceeded, ps.spfLookupCount = evaluateSPFState(spf)
	ps.dmarcOK, ps.dmarcWarning, ps.dmarcMissing, ps.dmarcHasRua, ps.dmarcPolicy, ps.dmarcPct = evaluateDMARCState(dmarc)
	ps.dmarcHasRuf, ps.dmarcStrictAlign = dmarcReportingSignals(dmarc)

	// Tri-state honesty: a transient TXT lookup failure (SERVFAIL/timeout) is
	// neither configured nor absent. Track it explicitly so downstream
	// presence flags (hasSPF/hasDMARC) and email-spoofability verdicts never
	// treat an indeterminate measurement as a published record.
	if spf != nil {
		if st, _ := spf[mapKeySpfState].(string); st == statusIndeterminate {
			ps.spfIndeterminate = true
		}
	}
	if dmarc != nil {
		if st, _ := dmarc[mapKeyDmarcState].(string); st == statusIndeterminate {
			ps.dmarcIndeterminate = true
		}
	}
	ps.dkimOK, ps.dkimProvider, ps.dkimPartial, ps.dkimWeakKeys, ps.dkimThirdPartyOnly, ps.primaryProvider = evaluateDKIMState(dkim)

	ps.caaOK = evaluateSimpleProtocolState(caa, mapKeyStatus)
	ps.mtaStsOK = evaluateSimpleProtocolState(mtaSts, mapKeyStatus)
	ps.tlsrptOK = evaluateSimpleProtocolState(tlsrpt, mapKeyStatus)
	ps.bimiOK = evaluateSimpleProtocolState(bimi, mapKeyStatus)
	ps.caaIndeterminate = simpleProtocolIndeterminate(caa, mapKeyCaaState)
	ps.mtaStsIndeterminate = simpleProtocolIndeterminate(mtaSts, mapKeyMtaStsState)
	ps.tlsrptIndeterminate = simpleProtocolIndeterminate(tlsrpt, mapKeyTlsrptState)
	ps.bimiIndeterminate = simpleProtocolIndeterminate(bimi, mapKeyBimiState)

	evaluateDANEState(dane, &ps)
	evaluateDNSSECState(dnssec, &ps)

	return ps
}

func evaluateDANEState(dane map[string]any, ps *protocolState) {
	if isMissingRecord(dane) {
		return
	}
	// A transient TLSA/MX probe failure yields dane_state=indeterminate ("could
	// not verify"). Keep it neutral — it is NOT evidence DANE is absent (RFC
	// 7672), so it must never read as absent in posture or dock the score.
	if st, _ := dane["dane_state"].(string); st == daneStateIndeterminate {
		ps.daneIndeterminate = true
		return
	}
	if hasDane, ok := dane["has_dane"].(bool); ok && hasDane {
		ps.daneOK = true
	}
	if deployable, ok := dane["dane_deployable"].(bool); ok && !deployable {
		ps.daneProviderLimited = true
	}
}

func evaluateDNSSECState(dnssec map[string]any, ps *protocolState) {
	if isMissingRecord(dnssec) {
		return
	}
	// A transient DNSKEY/DS lookup failure yields dnssec_state=indeterminate
	// ("could not verify"). This must stay neutral — it is NOT evidence the zone
	// is unsigned (RFC 4035), so it must never read as absent in posture.
	if st, _ := dnssec[mapKeyDnssecState].(string); st == dnssecStateIndeterminate {
		ps.dnssecIndeterminate = true
		return
	}
	status, _ := dnssec[mapKeyStatus].(string)
	switch status {
	case mapKeySuccess:
		ps.dnssecOK = true
	case "error":
		ps.dnssecBroken = true
	}
	// AD flag: did a validating resolver actually confirm the chain of trust?
	// dnssecOK is true whenever DNSKEY+DS are present, even when the resolver did
	// NOT set AD — so the verdict must distinguish "signed" from "validated".
	if ad, ok := dnssec[mapKeyAdFlag].(bool); ok {
		ps.dnssecADValidated = ad
	}
	if obs, ok := dnssec["algorithm_observation"].(map[string]any); ok {
		if s, ok := obs["strength"].(string); ok {
			ps.dnssecAlgoStrength = s
		}
	}
}

func detectProbableNoMail(results map[string]any) bool {
	basic, _ := results["basic_records"].(map[string]any)
	if basic == nil {
		return false
	}
	mxRecords, _ := basic["MX"].([]string)
	if len(mxRecords) > 0 {
		return false
	}
	mxAny, _ := results["mx_records"].([]any)
	if len(mxAny) > 0 {
		return false
	}
	return true
}

func isMissingRecord(m map[string]any) bool {
	if m == nil {
		return true
	}
	status, _ := m[mapKeyStatus].(string)
	return status == "error" || status == "missing" || status == "n/a"
}

func hasNonEmptyString(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	s, ok := m[key].(string)
	return ok && s != ""
}

func extractIntField(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	}
	return 0
}

func extractIntFieldDefault(m map[string]any, key string, defaultVal int) int {
	if m == nil {
		return defaultVal
	}
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	}
	return defaultVal
}

func evaluateDKIMIssues(dkim map[string]any) (weakKeys, thirdPartyOnly bool) {
	if dkim == nil {
		return false, false
	}

	if wk, ok := dkim["weak_keys"].(bool); ok && wk {
		weakKeys = true
	}
	if tpo, ok := dkim["third_party_only"].(bool); ok && tpo {
		thirdPartyOnly = true
	}

	if issues, ok := dkim[mapKeyIssues].([]any); ok {
		wk, tpo := scanDKIMIssueStrings(issues)
		if wk {
			weakKeys = true
		}
		if tpo {
			thirdPartyOnly = true
		}
	}

	return weakKeys, thirdPartyOnly
}

func scanDKIMIssueStrings(issues []any) (weakKeys, thirdPartyOnly bool) {
	for _, issue := range issues {
		s, ok := issue.(string)
		if !ok {
			continue
		}
		lower := strings.ToLower(s)
		if strings.Contains(lower, "weak") || strings.Contains(lower, "1024") {
			weakKeys = true
		}
		if strings.Contains(lower, "third-party") || strings.Contains(lower, "third party") {
			thirdPartyOnly = true
		}
	}
	return
}

func classifySPF(ps protocolState, acc *postureAccumulator) {
	if ps.spfMissing {
		acc.issues = append(acc.issues, "No SPF record published — RFC 7208 defines the SPF mechanism but does not mandate publication. Without SPF, any server can send email claiming to be this domain (CVE-2024-7208, CVE-2024-7209)")
		acc.recommendations = append(acc.recommendations, "Publish an SPF record to authorize legitimate mail senders")
		acc.absent = append(acc.absent, rtSPF)
		return
	}

	if ps.spfDangerous {
		acc.issues = append(acc.issues, "SPF record uses +all — allows any server to send mail as this domain (RFC 7208 §5.1 defines +all as passing all senders)")
		acc.recommendations = append(acc.recommendations, "Change SPF mechanism from +all to ~all or -all")
		acc.configured = append(acc.configured, rtSPF)
		return
	}

	if ps.spfLookupExceeded {
		acc.issues = append(acc.issues, fmt.Sprintf("SPF record exceeds 10-lookup limit (%d lookups)", ps.spfLookupCount))
		acc.recommendations = append(acc.recommendations, "Reduce SPF lookup count to 10 or fewer using IP-based mechanisms")
	}

	if ps.spfNeutral {
		acc.recommendations = append(acc.recommendations, "SPF uses ?all (neutral) — consider ~all or -all for stronger policy")
	}

	if ps.spfWarning && !ps.spfHardFail {
		acc.monitoring = append(acc.monitoring, "SPF configured with soft fail (~all) — industry-standard when paired with DMARC enforcement (RFC 7489)")
	}

	if ps.spfHardFail {
		acc.configured = append(acc.configured, "SPF (hard fail)")
	} else if ps.spfOK {
		acc.configured = append(acc.configured, rtSPF)
	}
}

func classifyDMARC(ps protocolState, acc *postureAccumulator) {
	if ps.dmarcMissing {
		acc.issues = append(acc.issues, "No DMARC record published — RFC 7489 is Informational (not Standards Track); DMARCbis will elevate to Standards Track. Without DMARC, receivers have no policy for handling SPF/DKIM failures — spoofed mail may be delivered (CVE-2024-49040)")
		acc.recommendations = append(acc.recommendations, "Publish a DMARC record starting with p=none and rua reporting")
		acc.absent = append(acc.absent, "DMARC")
		return
	}

	if ps.dmarcOK && !ps.dmarcWarning {
		classifyDMARCSuccess(ps, acc)
	} else if ps.dmarcWarning {
		classifyDMARCWarning(ps, acc)
	}
}

func classifyDMARCSuccess(ps protocolState, acc *postureAccumulator) {
	switch ps.dmarcPolicy {
	case mapKeyReject:
		// pct= applies to reject too (RFC 7489) — mirror the quarantine
		// branch so a partial or zero pct is never listed as full reject.
		switch {
		case ps.dmarcPct >= 100:
			acc.configured = append(acc.configured, "DMARC (reject)")
		case ps.dmarcPct > 0:
			acc.configured = append(acc.configured, fmt.Sprintf("DMARC (reject, %d%%)", ps.dmarcPct))
			acc.monitoring = append(acc.monitoring, fmt.Sprintf("DMARC reject policy only applies to %d%% of messages", ps.dmarcPct))
			acc.recommendations = append(acc.recommendations, "Increase DMARC pct to 100 for full enforcement")
		default:
			acc.configured = append(acc.configured, "DMARC (reject, pct=0)")
			acc.issues = append(acc.issues, "DMARC policy is reject with pct=0 — enforcement applies to 0% of mail, so nothing is blocked (RFC 7489 §6.3)")
			acc.recommendations = append(acc.recommendations, "Raise DMARC pct so the reject policy actually applies")
		}
	case mapKeyQuarantine:
		switch {
		case ps.dmarcPct >= 100:
			acc.configured = append(acc.configured, "DMARC (quarantine, 100%)")
			acc.recommendations = append(acc.recommendations, "Upgrade DMARC policy from quarantine to reject (p=reject) for maximum spoofing protection")
		case ps.dmarcPct > 0:
			acc.configured = append(acc.configured, fmt.Sprintf("DMARC (quarantine, %d%%)", ps.dmarcPct))
			acc.monitoring = append(acc.monitoring, fmt.Sprintf("DMARC quarantine policy only applies to %d%% of messages", ps.dmarcPct))
			acc.recommendations = append(acc.recommendations, "Increase DMARC pct to 100 for full enforcement")
		default:
			// pct=0: zero enforcement is an issue, not a monitoring note —
			// symmetric with the reject branch above.
			acc.configured = append(acc.configured, "DMARC (quarantine, pct=0)")
			acc.issues = append(acc.issues, "DMARC policy is quarantine with pct=0 — enforcement applies to 0% of mail, so nothing is blocked (RFC 7489 §6.3)")
			acc.recommendations = append(acc.recommendations, "Raise DMARC pct so the quarantine policy actually applies")
		}
	case statusNone:
		acc.configured = append(acc.configured, "DMARC (monitoring only)")
		if ps.dmarcHasRua {
			acc.monitoring = append(acc.monitoring, "DMARC policy is 'none' (monitoring mode) — receiving aggregate reports")
			acc.recommendations = append(acc.recommendations, "Review DMARC aggregate reports and move to quarantine or reject policy")
		} else {
			acc.issues = append(acc.issues, "DMARC policy is 'none' with no reporting — provides no protection or visibility")
			acc.recommendations = append(acc.recommendations, "Add rua tag to receive DMARC aggregate reports before enforcing policy")
		}
	default:
		acc.configured = append(acc.configured, "DMARC")
	}

	// A domain explicitly marked as not handling mail (null MX per RFC 7505, or
	// an otherwise detected no-mail domain) carries no legitimate mail flow, so
	// DMARC aggregate reporting yields no "visibility into email authentication."
	// Recommending it on a correct no-mail lockdown (e.g. null MX + p=reject) is
	// noise — suppress it for no-mail domains.
	if !ps.dmarcHasRua && ps.dmarcPolicy != statusNone && !ps.isNoMailDomain {
		acc.recommendations = append(acc.recommendations, "Add DMARC aggregate reporting (rua) for visibility into email authentication")
	}
}

func classifyDMARCWarning(ps protocolState, acc *postureAccumulator) {
	acc.configured = append(acc.configured, "DMARC (with warnings)")
	acc.monitoring = append(acc.monitoring, "DMARC record has configuration warnings — review recommended")

	if ps.dmarcPolicy == statusNone {
		acc.recommendations = append(acc.recommendations, "Move DMARC policy from 'none' to 'quarantine' or 'reject'")
	}
	// No-mail domains gain no email-authentication visibility from rua (see
	// classifyDMARCSuccess) — do not recommend it for them.
	if !ps.dmarcHasRua && !ps.isNoMailDomain {
		acc.recommendations = append(acc.recommendations, "Enable DMARC aggregate reporting (rua) for authentication visibility")
	}
}

func classifyDKIMPosture(ds DKIMState, primaryProvider string, acc *postureAccumulator) {
	switch ds {
	case DKIMSuccess:
		acc.configured = append(acc.configured, "DKIM")
	case DKIMProviderInferred:
		acc.configured = append(acc.configured, fmt.Sprintf("DKIM (inferred via %s)", primaryProvider))
		acc.monitoring = append(acc.monitoring, "DKIM signing inferred from provider — could not directly verify selector")
	case DKIMThirdPartyOnly:
		acc.configured = append(acc.configured, "DKIM (third-party only)")
		acc.recommendations = append(acc.recommendations, "Configure DKIM signing for your primary domain selector in addition to third-party services")
	case DKIMWeakKeysOnly:
		acc.configured = append(acc.configured, "DKIM (weak keys)")
		acc.issues = append(acc.issues, "DKIM keys are weak (1024-bit or less) — RFC 6376 §3.3.3 requires minimum 1024-bit RSA; 2048-bit is the current operational standard. Keys below 1024-bit are considered cryptographically breakable")
		acc.recommendations = append(acc.recommendations, "Upgrade DKIM keys to 2048-bit RSA or Ed25519")
	case DKIMNoMailDomain:
		acc.configured = append(acc.configured, "DKIM (not applicable — no-mail domain)")
	case DKIMInconclusive:
		// NOT appended to acc.absent. DKIM selectors are not enumerable from
		// DNS — a selector is discoverable only if you already know its name,
		// so probing a list of common ones and finding nothing proves the
		// domain does not use THOSE names, never that it does not sign.
		// Measured 2026-07-31: Google's published selector 20230601 resolves
		// on gmail.com and google.com and nothing on icloud.com or apple.com,
		// which shows only that Apple uses different selector names.
		//
		// acc.absent feeds the "N not configured" count, so listing an
		// unverifiable control there reported a guess as a measurement. The
		// monitoring note carries it instead: visible, flagged as needing
		// attention, counted as neither configured nor absent.
		acc.monitoring = append(acc.monitoring, fmt.Sprintf(
			"DKIM status is inconclusive — no record was found at any of the %d common selector names this tool probes. DKIM selectors are arbitrary labels with no enumerating DNS record (RFC 6376), so this is not evidence that DKIM is absent. To resolve it, find the selector: the s= value in the DKIM-Signature header of any email from this domain (RFC 6376 §3.5), the record at <selector>._domainkey.<domain>, or your mail provider's DKIM setup console — then enter it and we'll verify.",
			len(defaultDKIMSelectors),
		))
	case DKIMAbsent:
		acc.absent = append(acc.absent, "DKIM")
		acc.recommendations = append(acc.recommendations, "Configure DKIM signing to cryptographically authenticate outgoing email — RFC 6376 defines the mechanism; without it, messages cannot be verified as unaltered in transit")
	}
}

func classifyPresence(ok bool, name string, acc *postureAccumulator) {
	if ok {
		acc.configured = append(acc.configured, name)
	} else {
		acc.absent = append(acc.absent, name)
	}
}

func classifyDANE(ps protocolState, acc *postureAccumulator) {
	if ps.daneOK {
		acc.configured = append(acc.configured, rtDANE)
	} else if ps.daneProviderLimited {
		acc.providerLimited = append(acc.providerLimited, rtDANE)
	} else {
		acc.absent = append(acc.absent, rtDANE)
	}
}

func classifyDNSSEC(ps protocolState, acc *postureAccumulator) {
	if ps.dnssecOK {
		acc.configured = append(acc.configured, "DNSSEC")
	} else if ps.dnssecBroken {
		acc.issues = append(acc.issues, "DNSSEC validation is failing — DNS responses cannot be trusted")
		acc.recommendations = append(acc.recommendations, "Fix DNSSEC configuration or remove broken DS records")
	} else if ps.dnssecIndeterminate {
		acc.monitoring = append(acc.monitoring, "DNSSEC could not be verified — DNSKEY/DS lookup did not complete; re-run before concluding the zone is unsigned (RFC 4035)")
	} else {
		acc.absent = append(acc.absent, "DNSSEC")
	}
}

func classifySimpleProtocols(ps protocolState, isTLD bool, acc *postureAccumulator) {
	if !isTLD {
		classifyPresenceTri(ps.mtaStsOK, ps.mtaStsIndeterminate, protocolMTASTS, acc)
		classifyPresenceTri(ps.tlsrptOK, ps.tlsrptIndeterminate, protocolTLSRPT, acc)
		classifyPresenceTri(ps.bimiOK, ps.bimiIndeterminate, "BIMI", acc)
		classifyDANE(ps, acc)
	}

	classifyDNSSEC(ps, acc)

	if !isTLD {
		classifyPresenceTri(ps.caaOK, ps.caaIndeterminate, "CAA", acc)
	}
}

// simpleProtocolIndeterminate reports whether a simple-record analyzer result
// carries a tri-state of indeterminate — its DNS lookup did not complete, so the
// posture layer must treat it as "could not verify", never as a confirmed
// absence.
func simpleProtocolIndeterminate(result map[string]any, stateKey string) bool {
	if result == nil {
		return false
	}
	state, _ := result[stateKey].(string)
	return state == triStateIndeterminate
}

// classifyPresenceTri extends classifyPresence with the indeterminate tri-state:
// a record whose lookup did not complete is routed to monitoring ("could not
// verify"), never to the absent bucket, so a transient DNS failure can never be
// reported as a confirmed missing control.
func classifyPresenceTri(ok, indeterminate bool, name string, acc *postureAccumulator) {
	if indeterminate {
		acc.monitoring = append(acc.monitoring, name+" could not be verified — the DNS lookup did not complete; re-run before concluding it is absent")
		return
	}
	classifyPresence(ok, name, acc)
}

func classifyDanglingDNS(results map[string]any, acc *postureAccumulator) {
	dangling, ok := results["dangling_dns"].(map[string]any)
	if !ok {
		return
	}
	count := extractIntField(dangling, "dangling_count")
	if count > 0 {
		acc.issues = append(acc.issues, fmt.Sprintf("%d dangling DNS record(s) detected — potential subdomain takeover risk", count))
		acc.recommendations = append(acc.recommendations, "Review and remove dangling DNS records pointing to deprovisioned services")
	}
}

func classifyDMARCReportAuth(results map[string]any, acc *postureAccumulator) {
	reportAuth, ok := results["dmarc_report_auth"].(map[string]any)
	if !ok {
		return
	}

	issues, _ := reportAuth[mapKeyIssues].([]string)
	for _, issue := range issues {
		acc.monitoring = append(acc.monitoring, issue)
	}

	externalDomains := extractExternalDomainMaps(reportAuth["external_domains"])
	for _, ed := range externalDomains {
		if authorized, ok := ed["authorized"].(bool); ok && !authorized {
			domain, _ := ed["domain"].(string)
			if domain != "" {
				acc.recommendations = append(acc.recommendations, fmt.Sprintf("Authorize external DMARC reporting for %s or remove from rua/ruf", domain))
			}
		}
	}
}

func extractExternalDomainMaps(raw any) []map[string]any {
	if raw == nil {
		return nil
	}
	if arr, ok := raw.([]map[string]any); ok {
		return arr
	}
	if arr, ok := raw.([]any); ok {
		result := make([]map[string]any, 0, len(arr))
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				result = append(result, m)
			}
		}
		return result
	}
	return nil
}

var freeCAs = map[string]bool{
	"Let's Encrypt": true,
	"ZeroSSL":       true,
	"Buypass":       true,
	"Google Trust":  true,
	"E1":            true,
	"R3":            true,
	"R10":           true,
	"R11":           true,
	"ISRG Root":     true,
	"WE1":           true,
	"Amazon":        true,
	"AWS":           true,
	"Cloudflare":    true,
}

func matchesFreeCertAuthority(caName string) bool {
	if freeCAs[caName] {
		return true
	}
	lower := strings.ToLower(caName)
	for free := range freeCAs {
		if strings.Contains(lower, strings.ToLower(free)) {
			return true
		}
	}
	return false
}

func classifyCertificateCosts(results map[string]any, acc *postureAccumulator) {
	ct, ok := results["ct_subdomains"].(map[string]any)
	if !ok {
		return
	}

	caSummaryRaw, ok := ct["ca_summary"]
	if !ok {
		return
	}

	caSummary, ok := caSummaryRaw.([]map[string]any)
	if !ok {
		return
	}

	hasWildcard := false
	if wc, ok := ct["wildcard_certs"].(map[string]any); ok {
		if present, ok := wc["present"].(bool); ok && present {
			hasWildcard = true
		}
	}

	totalPaidCerts := 0
	paidCANames := []string{}
	hasFreeCerts := false
	for _, ca := range caSummary {
		name, _ := ca["name"].(string)
		count := extractIntField(ca, "certCount")
		if matchesFreeCertAuthority(name) {
			hasFreeCerts = true
		} else if count > 0 {
			totalPaidCerts += count
			paidCANames = append(paidCANames, name)
		}
	}

	if totalPaidCerts >= 3 && !hasWildcard {
		acc.recommendations = append(acc.recommendations,
			fmt.Sprintf("Consider a wildcard certificate (*.domain) to reduce certificate management overhead — %d individual certificates detected across %s",
				totalPaidCerts, strings.Join(paidCANames, ", ")))
	}

	if totalPaidCerts >= 3 && !hasFreeCerts {
		acc.recommendations = append(acc.recommendations,
			"Evaluate free certificate providers (Let's Encrypt, AWS Certificate Manager) — automated issuance and renewal can reduce costs, especially with shorter certificate lifetimes ahead")
	}
}

// deliberatenessEvidence separates the two ways a non-maximal DMARC policy can
// be a considered choice rather than an unfinished rollout:
//
//   - collection: the operator is tuned to HARVEST. ruf= is the strongest tell
//     (DMARCbis removed it; the large receivers ignore it; publishing it is a
//     deliberate request for forensics from whatever minority still answers).
//   - maturity: the operator plainly knows how to do this, so an unfinished
//     rollout is the less likely reading — they have some other reason.
//
// Only signals INDEPENDENT of the gate count. rua= is excluded on purpose: the
// caller already requires it, so counting it would be circular — which is the
// exact defect this replaces.
func deliberatenessEvidence(ps protocolState) (collection []string, maturity []string) {
	if ps.dmarcHasRuf {
		collection = append(collection, "forensic reporting (ruf=), which DMARCbis removed and most large receivers no longer honour")
	}
	if ps.tlsrptOK {
		collection = append(collection, "TLS-RPT transport failure reporting")
	}
	if ps.dmarcStrictAlign {
		collection = append(collection, "strict alignment on both SPF and DKIM, where relaxed is the default")
	}
	if ps.dnssecOK {
		maturity = append(maturity, "a validating DNSSEC chain")
	}
	if ps.mtaStsOK {
		maturity = append(maturity, "MTA-STS")
	}
	if ps.caaOK {
		maturity = append(maturity, "CAA")
	}
	if ps.bimiOK {
		maturity = append(maturity, "BIMI")
	}
	if ps.spfHardFail {
		maturity = append(maturity, "an SPF -all hard fail")
	}
	return collection, maturity
}

// deliberatenessCorroborationBar is the number of independent signals required
// before the tool will describe a policy choice as possibly deliberate. Two is
// judgement, not a measured threshold: the base rate of these combinations in
// the wild has not been measured, so this is deliberately conservative — ICD
// 203 prefers understating confidence to overstating it.
const deliberatenessCorroborationBar = 2

func evaluateDeliberateMonitoring(ps protocolState) (bool, string) {
	if !ps.dmarcOK || !ps.dmarcHasRua || !ps.spfOK {
		return false, ""
	}
	// The previous bar was `configuredCount >= 2`, which could never fail:
	// reaching this line already requires SPF and DMARC, and both append to
	// acc.configured. A check implied by its own gate is not corroboration,
	// so in practice every qualifying domain received the hedge.
	collection, maturity := deliberatenessEvidence(ps)
	if len(collection)+len(maturity) < deliberatenessCorroborationBar {
		return false, ""
	}
	evidence := describeDeliberatenessEvidence(collection, maturity)
	// Every branch states the practical consequence for someone RECEIVING
	// mail from this domain. A hedge about the operator's intent must never
	// leave a reader believing the domain is therefore safe to trust —
	// under none and under quarantine, spoofed mail still reaches them.
	switch {
	case ps.dmarcPolicy == statusNone:
		return true, "DMARC is published at p=none with aggregate reporting enabled (RFC 7489 §6.3) — authentication results are reported but no enforcement is requested. " +
			evidence +
			" It's possible this organization is deliberately prioritising observation over enforcement. What this means if you receive mail from this domain: p=none blocks nothing — a spoofed message that fails authentication is delivered to the inbox exactly as it would be with no DMARC record at all. Moving to quarantine or reject adds protection while aggregate reporting continues unchanged."
	case ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct < 100:
		return true, fmt.Sprintf("DMARC quarantine is enforced at %d%% with aggregate reporting (RFC 7489 §6.3). Quarantine accepts failing mail for inspection rather than refusing it at delivery. ", ps.dmarcPct) +
			evidence +
			fmt.Sprintf(" It's possible this organization values that message-level visibility over outright rejection. What this means if you receive mail from this domain: roughly %d%% of messages that fail authentication are filtered to a spam or junk folder rather than refused, and the remaining %d%% are delivered normally. Spoofed mail from this domain can still reach you.", ps.dmarcPct, 100-ps.dmarcPct)
	case ps.dmarcPolicy == mapKeyQuarantine:
		return true, "DMARC quarantine is fully enforced (100%) with aggregate reporting (RFC 7489 §6.3). Unlike p=reject, which refuses unauthenticated mail at delivery, quarantine still accepts it for inspection. " +
			evidence +
			" It's possible this organization values that retained message-level visibility over pure rejection. What this means if you receive mail from this domain: messages that fail authentication are still delivered — typically to a spam or junk folder — not refused. A domain at p=quarantine is not a domain from which spoofed mail cannot reach you. p=reject remains the strongest anti-spoofing posture if message-level inspection is not a deliberate requirement; aggregate reporting is unaffected by either policy."
	}
	return false, ""
}

// describeDeliberatenessEvidence names what the judgement rests on, so a reader
// can check the reasoning instead of taking the verdict on trust — the analytic
// standard's requirement to distinguish the underlying observation from the
// judgement drawn from it. (The standard is named only in the centralised
// methodology constants; see the guard in methodology_const_test.go.)
func describeDeliberatenessEvidence(collection, maturity []string) string {
	switch {
	case len(collection) > 0 && len(maturity) > 0:
		return "This is not a default configuration: the record also carries " + joinPhrases(collection) +
			", and the domain separately deploys " + joinPhrases(maturity) + "."
	case len(collection) > 0:
		return "This is not a default configuration: the record also carries " + joinPhrases(collection) + "."
	case len(maturity) > 0:
		return "The domain separately deploys " + joinPhrases(maturity) + ", so an unfinished rollout is the less likely reading."
	}
	return ""
}

func joinPhrases(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
}

func (a *Analyzer) CalculatePosture(results map[string]any) map[string]any {
	isTLD, _ := results["is_tld"].(bool)
	ps := evaluateProtocolStates(results)
	ds := classifyDKIMState(ps)

	acc := &postureAccumulator{
		issues:          []string{},
		recommendations: []string{},
		monitoring:      []string{},
		configured:      []string{},
		absent:          []string{},
		providerLimited: []string{},
	}

	if !isTLD {
		classifySPF(ps, acc)
		classifyDMARC(ps, acc)
		classifyDKIMPosture(ds, ps.primaryProvider, acc)
	}
	classifySimpleProtocols(ps, isTLD, acc)
	classifyDanglingDNS(results, acc)
	classifyDMARCReportAuth(results, acc)
	classifyCertificateCosts(results, acc)

	// Present-only: a record counts as present only when neither absent nor
	// indeterminate. Using !missing alone would let a transient lookup failure
	// (indeterminate) masquerade as a published record in email-spoofability
	// verdicts and the BIG Questions summary.
	hasSPF := !ps.spfMissing && !ps.spfIndeterminate
	hasDMARC := !ps.dmarcMissing && !ps.dmarcIndeterminate
	hasDKIM := ds.IsPresent()

	if isTLD {
		hasSPF = true
		hasDMARC = true
		hasDKIM = true
		ps.isNoMailDomain = true
		ps.isTLD = true
	}

	gi := gradeInput{
		hasSPF:     hasSPF,
		hasDMARC:   hasDMARC,
		hasDKIM:    hasDKIM,
		monitoring: acc.monitoring,
		configured: acc.configured,
		absent:     acc.absent,
	}

	state, icon, color, message := determineGrade(ps, ds, gi)

	// The email-spoofing consequence axis, exposed so consumers (history rows,
	// the critical owl, report surfaces) can read the consequence from its
	// producer instead of re-deriving it from record presence. "open" means a
	// spoofed message is delivered with nothing blocking it. It describes the
	// spoofing door ONLY: a DNSSEC-broken grade colours danger on the
	// DNS-integrity axis and can coexist with spoof_door "closed". TLDs are
	// graded on the registry axis, so the door does not apply.
	spoofDoorState := "not_applicable"
	if !isTLD {
		spoofDoorState = doorString(classifySpoofDoor(ps, hasSPF, hasDMARC))
	}

	score := computeInternalScore(ps, ds)

	vi := verdictInput{ps: ps, ds: ds, hasSPF: hasSPF, hasDMARC: hasDMARC, hasDKIM: hasDKIM}
	verdicts := buildVerdicts(vi)
	buildAISurfaceVerdicts(results, verdicts)

	deliberate, deliberateNote := evaluateDeliberateMonitoring(ps)

	var criticalIssues []string
	if ps.dnssecBroken {
		criticalIssues = append(criticalIssues, "DNSSEC validation is failing")
	}
	if !isTLD && ps.spfMissing && ps.dmarcMissing {
		criticalIssues = append(criticalIssues, "No SPF and no DMARC — domain is completely unprotected against email spoofing. Both protocols are RFC-recommended (not mandatory), but their absence leaves the domain open to impersonation (CVE-2024-7208, CVE-2024-49040)")
	}

	grade := state
	label := state

	return map[string]any{
		"score":                      score,
		"grade":                      grade,
		mapKeyLabel:                  label,
		"state":                      state,
		mapKeyIcon:                   icon,
		mapKeyColor:                  color,
		"spoof_door":                 spoofDoorState,
		"message":                    message,
		mapKeyIssues:                 acc.issues,
		"critical_issues":            criticalIssues,
		"recommendations":            acc.recommendations,
		"monitoring":                 acc.monitoring,
		"configured":                 acc.configured,
		"absent":                     acc.absent,
		"provider_limited":           acc.providerLimited,
		"dkim_inconclusive":          ds == DKIMInconclusive,
		"deliberate_monitoring":      deliberate,
		"deliberate_monitoring_note": deliberateNote,
		"verdicts":                   verdicts,
	}
}

func determineGrade(ps protocolState, ds DKIMState, gi gradeInput) (state, icon, color, message string) {
	gi.corePresent = gi.hasSPF && gi.hasDMARC
	// pct= applies to reject exactly as to quarantine (RFC 7489): reject at
	// pct=50 enforces half the stream, reject at pct=0 enforces nothing.
	// "reject means enforcing" without the pct check graded a rollback trick
	// as a closed door.
	enforcingPolicy := ps.dmarcPolicy == mapKeyReject || ps.dmarcPolicy == mapKeyQuarantine
	gi.dmarcFullEnforcing = enforcingPolicy && ps.dmarcPct >= 100
	gi.dmarcPartialEnforcing = enforcingPolicy && ps.dmarcPct < 100
	gi.dmarcStrict = ps.dmarcPolicy == mapKeyReject && ps.dmarcPct >= 100
	gi.hasCAA = ps.caaOK
	gi.dkimInconclusive = ds == DKIMInconclusive
	gi.isNoMail = ps.isNoMailDomain

	state, icon, color, message = classifyGrade(ps, gi)
	return
}

func classifyGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
	if ps.dnssecBroken {
		return riskCritical, iconExclamationTriangle, mapKeyDanger, "DNSSEC validation is broken — DNS responses may be tampered with"
	}

	if ps.isTLD {
		return classifyRegistryGrade(ps, gi)
	}

	if gi.isNoMail {
		return classifyNoMailGrade(ps, gi)
	}

	return classifyMailGrade(ps, gi)
}

// spoofDoor is the operational-consequence axis of the email-security grade:
// not "which records exist" (compliance) but "what happens to a spoofed
// message today" (operation). The mail-grade colour derives from this axis,
// never from the spec's tone — RFC-optional does not mean operationally mild,
// and the two had drifted: a domain whose own spoofability verdict renders
// "Yes" in danger was carrying a warning-amber grade because its missing
// record is optional per RFC 7208. (DNSSEC-broken and registry grades colour
// on their own axes — this one is about the spoofing door.)
type spoofDoor int

const (
	// doorUnknown: an SPF/DMARC lookup did not complete — consequence unknowable.
	doorUnknown spoofDoor = iota
	// doorClosed: enforcement is requested for the full mail stream (p=reject,
	// or p=quarantine at 100%).
	doorClosed
	// doorGuarded: enforcement exists but with a gap a spoofed message can
	// exploit (partial quarantine pct, or enforcement resting on DKIM alone).
	doorGuarded
	// doorOpen: nothing blocks a spoofed message — no policy, or p=none.
	// Delivered to the inbox exactly as if no records existed.
	doorOpen
	// doorNoMail: null-MX / no-mail domain — spoofability is graded by the
	// dedicated no-mail branch instead.
	doorNoMail
)

// classifySpoofDoor derives the door state from the same producer the
// spoofability verdict uses, so the grade colour and the "Can email be
// spoofed?" answer can never disagree again. emailSpoofDMARCOnly needs the
// policy split the verdict class does not carry: DMARC without SPF still
// enforces when DKIM aligns (guarded), but at p=none it enforces nothing
// (open).
func classifySpoofDoor(ps protocolState, hasSPF, hasDMARC bool) spoofDoor {
	switch classifyEmailSpoofability(ps, hasSPF, hasDMARC) {
	case emailSpoofIndeterminate:
		return doorUnknown
	case emailSpoofNoMail:
		return doorNoMail
	case emailSpoofReject, emailSpoofQuarantineFull:
		return doorClosed
	case emailSpoofQuarantinePartial, emailSpoofRejectPartial:
		return doorGuarded
	case emailSpoofDMARCOnly:
		// The guard needs pct too: reject/quarantine at pct=0 enforces
		// nothing, so DKIM alignment has no policy to trigger.
		if (ps.dmarcPolicy == mapKeyReject || ps.dmarcPolicy == mapKeyQuarantine) && ps.dmarcPct > 0 {
			return doorGuarded
		}
		return doorOpen
	default: // unprotected, monitorOnly, spfOnly, uncertain
		return doorOpen
	}
}

// doorColor maps the consequence axis to the display colour. This is the only
// place grade colour and spoofing consequence meet — branches below must use
// it rather than hand-assigning a colour token, so a future branch cannot
// reintroduce the optional-therefore-amber drift.
func doorColor(d spoofDoor) string {
	switch d {
	case doorClosed:
		return mapKeySuccess
	case doorGuarded:
		return mapKeyWarning
	case doorOpen:
		return mapKeyDanger
	default:
		return mapKeySecondary
	}
}

func doorString(d spoofDoor) string {
	switch d {
	case doorClosed:
		return "closed"
	case doorGuarded:
		return "guarded"
	case doorOpen:
		return "open"
	case doorNoMail:
		return "no_mail"
	default:
		return "unknown"
	}
}

func classifyMailGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
	// A transient SPF/DMARC lookup failure leaves hasSPF/hasDMARC false, but
	// that is "unknown", not "absent". Grading absence-based risk off an
	// unverified measurement would fabricate a verdict (RFC 7208 §4.6 /
	// RFC 7489 §6.6.3) — report inconclusive instead.
	if ps.spfIndeterminate || ps.dmarcIndeterminate {
		return riskMedium, "question", mapKeySecondary, "Email authentication could not be verified — a DNS lookup did not complete; re-run before concluding"
	}
	if !gi.hasSPF && !gi.hasDMARC {
		return riskCritical, iconExclamationTriangle, mapKeyDanger, "No SPF or DMARC records — domain is unprotected against email spoofing"
	}

	if !gi.hasSPF || !gi.hasDMARC {
		return classifyMailPartial(ps, gi)
	}

	return classifyMailCorePresent(ps, gi)
}

func classifyMailCorePresent(ps protocolState, gi gradeInput) (string, string, string, string) {
	if gi.dmarcFullEnforcing && gi.hasDKIM {
		state := riskLow
		msg := buildDescriptiveMessage(ps, gi.configured, gi.absent, gi.monitoring)
		return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, mapKeySuccess, msg
	}

	if gi.dmarcFullEnforcing && !gi.hasDKIM {
		state := riskMedium
		msg := "SPF and DMARC enforcing but DKIM not confirmed"
		return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, statusInfoPosture, msg
	}

	if gi.dmarcPartialEnforcing {
		// doorGuarded: the uncovered pct is delivered normally — a real gap,
		// so the colour is warning, not the informational tone it carried
		// when colour followed the spec's optionality rather than the gap.
		// pct=0 is zero enforcement, not a gap — the door classifier returns
		// open for it, and the colour follows.
		state := riskMedium
		msg := fmt.Sprintf("DMARC %s at %d%% — not fully enforcing", ps.dmarcPolicy, ps.dmarcPct)
		if ps.dmarcPct <= 0 {
			msg = fmt.Sprintf("DMARC %s at 0%% — requests no enforcement at all", ps.dmarcPolicy)
		}
		return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, doorColor(classifySpoofDoor(ps, gi.hasSPF, gi.hasDMARC)), msg
	}

	if ps.dmarcPolicy == statusNone {
		if ps.dmarcHasRua {
			// Tier stays Medium (monitoring maturity is real posture), but the
			// colour follows the consequence: p=none blocks nothing, and the
			// spoofability verdict for this exact shape already answers "Yes"
			// in danger. Grade and verdict must not disagree on one screen.
			state := riskMedium
			msg := "DMARC is in monitoring mode (p=none) with reporting enabled — no enforcement is requested, so a spoofed message is delivered as if no DMARC existed (RFC 7489 §6.3)"
			return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, mapKeyDanger, msg
		}
		return riskHigh, iconExclamationTriangle, mapKeyDanger, "DMARC policy is 'none' with no reporting — no protection or visibility"
	}

	state := riskMedium
	msg := buildDescriptiveMessage(ps, gi.configured, gi.absent, gi.monitoring)
	return applyMonitoringSuffix(state, gi.monitoring), iconShieldAlt, doorColor(classifySpoofDoor(ps, gi.hasSPF, gi.hasDMARC)), msg
}

func classifyMailPartial(ps protocolState, gi gradeInput) (string, string, string, string) {
	if gi.hasSPF && !gi.hasDMARC {
		// No DMARC means no policy for failures at all — the door is open
		// (emailSpoofSPFOnly answers "Likely" in danger), so the grade colour
		// says so too.
		return riskHigh, iconExclamationTriangle, mapKeyDanger, "SPF present but no DMARC — spoofed emails may still be delivered"
	}
	door := classifySpoofDoor(ps, gi.hasSPF, gi.hasDMARC)
	if door == doorOpen {
		return riskHigh, iconExclamationTriangle, mapKeyDanger, "DMARC present but no SPF, and the policy requests no enforcement — nothing is authenticated and nothing is blocked, so mail claiming this domain is delivered unchecked"
	}
	return riskHigh, iconExclamationTriangle, mapKeyWarning, "DMARC present but no SPF — mail authentication is incomplete"
}

func classifyNoMailGrade(ps protocolState, gi gradeInput) (string, string, string, string) {
	// Tri-state honesty (mirrors classifyRegistryGrade): a transient SPF/DMARC
	// lookup failure must never be reported as "missing" or "no records" for a
	// no-mail domain. Surface an explicit could-not-verify grade and ask for a
	// re-run before concluding the records are absent (RFC 7208, RFC 7489).
	if ps.spfIndeterminate || ps.dmarcIndeterminate {
		return riskMedium, iconShieldHalved, mapKeySecondary, "No-mail domain email authentication could not be fully verified — an SPF/DMARC lookup did not complete; re-run before concluding records are missing"
	}
	if gi.hasSPF && gi.hasDMARC {
		if gi.dmarcStrict || gi.dmarcFullEnforcing {
			return riskLow, iconShieldAlt, mapKeySuccess, "No-mail domain properly configured with SPF and DMARC reject policy"
		}
		// Same open-door rule as the partial branch below: quarantine still
		// enforces on the covered fraction (guarded), but p=none or pct=0
		// enforces nothing — records alone must not soften the colour, or
		// adding one record to a danger shape would flip it to info.
		if (ps.dmarcPolicy == mapKeyQuarantine || ps.dmarcPolicy == mapKeyReject) && ps.dmarcPct > 0 {
			return riskMedium, iconShieldAlt, mapKeyWarning, "No-mail domain has SPF and DMARC but the policy enforces only part of the mail stream"
		}
		return riskMedium, iconShieldAlt, mapKeyDanger, "No-mail domain has SPF and DMARC but the policy requests no enforcement — mail claiming this domain is delivered unchecked"
	}
	if gi.hasSPF || gi.hasDMARC {
		// Same consequence rule as mail domains: with no enforcing DMARC,
		// nothing instructs a receiver to refuse mail claiming this domain —
		// parked domains are spoofed precisely because nobody is watching.
		if gi.dmarcFullEnforcing || gi.dmarcStrict {
			return riskHigh, iconExclamationTriangle, mapKeyWarning, "No-mail domain is missing SPF or DMARC"
		}
		return riskHigh, iconExclamationTriangle, mapKeyDanger, "No-mail domain is missing SPF or DMARC and has no enforcing policy — mail claiming this domain is delivered unchecked"
	}
	return riskCritical, iconExclamationTriangle, mapKeyDanger, "No-mail domain has no email authentication records"
}

func classifyRegistryGrade(ps protocolState, _ gradeInput) (string, string, string, string) {
	if ps.dnssecOK {
		return riskLow, iconShieldAlt, mapKeySuccess, "Registry zone has DNSSEC signing active — delegation chain is cryptographically signed"
	}
	if ps.dnssecIndeterminate {
		return riskMedium, iconShieldHalved, mapKeySecondary, "Registry zone DNSSEC could not be verified — DNSKEY/DS lookup did not complete; re-run before concluding the zone is unsigned"
	}
	return riskHigh, iconExclamationTriangle, mapKeyWarning, "Registry zone is not DNSSEC-signed — delegation chain lacks cryptographic verification"
}

func applyMonitoringSuffix(state string, monitoring []string) string {
	if len(monitoring) > 0 {
		return state
	}
	return state
}

func buildDescriptiveMessage(ps protocolState, configured, absent, monitoring []string) string {
	parts := []string{}

	if len(configured) > 0 {
		parts = append(parts, fmt.Sprintf("%d protocols configured", len(configured)))
	}
	if len(absent) > 0 {
		parts = append(parts, fmt.Sprintf("%d not configured", len(absent)))
	}
	if len(monitoring) > 0 {
		parts = append(parts, fmt.Sprintf("%d need attention", len(monitoring)))
	}

	if len(parts) == 0 {
		return "Email security posture evaluated"
	}

	return strings.Join(parts, ", ")
}

type verdictInput struct {
	ps       protocolState
	ds       DKIMState
	hasSPF   bool
	hasDMARC bool
	hasDKIM  bool
}

func buildVerdicts(vi verdictInput) map[string]any {
	verdicts := map[string]any{}

	buildEmailVerdict(vi, verdicts)
	buildBrandVerdict(vi.ps, verdicts)
	buildDNSVerdict(vi.ps, verdicts)
	buildCAAVerdict(vi.ps, verdicts)

	verdicts["email_answer"] = buildEmailAnswer(vi.ps, vi.hasSPF, vi.hasDMARC)
	ea := buildEmailAnswerStructured(vi.ps, vi.hasSPF, vi.hasDMARC)
	verdicts["email_answer_short"] = ea[mapKeyAnswer]
	verdicts["email_answer_reason"] = ea[mapKeyReason]
	verdicts["email_answer_color"] = ea[mapKeyColor]

	buildTransportVerdict(vi.ps, verdicts)

	return verdicts
}

func buildCAAVerdict(ps protocolState, verdicts map[string]any) {
	if ps.caaIndeterminate {
		verdicts["certificate_control"] = map[string]any{
			mapKeyLabel:  "Could Not Verify",
			mapKeyColor:  mapKeySecondary,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: "Unknown",
			mapKeyReason: "CAA records could not be verified — the DNS lookup did not complete (transient resolver failure); re-run before concluding any certificate authority may issue",
		}
		return
	}
	if ps.caaOK {
		verdicts["certificate_control"] = map[string]any{
			mapKeyLabel:  "Configured",
			mapKeyColor:  mapKeySuccess,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: answerYes,
			mapKeyReason: "CAA records restrict which certificate authorities may issue certificates",
		}
	} else {
		verdicts["certificate_control"] = map[string]any{
			mapKeyLabel:  "Not Configured",
			mapKeyColor:  mapKeySecondary,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: "No",
			mapKeyReason: "No CAA records — any certificate authority may issue certificates for this domain",
		}
	}
}

type emailSpoofClass int

const (
	emailSpoofNoMail emailSpoofClass = iota
	emailSpoofUnprotected
	emailSpoofReject
	emailSpoofQuarantineFull
	emailSpoofQuarantinePartial
	emailSpoofRejectPartial
	emailSpoofMonitorOnly
	emailSpoofSPFOnly
	emailSpoofDMARCOnly
	emailSpoofUncertain
	emailSpoofIndeterminate
)

func classifyEmailSpoofability(ps protocolState, hasSPF, hasDMARC bool) emailSpoofClass {
	if ps.isNoMailDomain {
		return emailSpoofNoMail
	}
	// A transient SPF/DMARC lookup failure makes the spoofability verdict
	// unknowable — we must not emit "Yes"/"No" off a measurement we could not
	// complete (RFC 7208 §4.6 / RFC 7489 §6.6.3). Report inconclusive.
	if ps.spfIndeterminate || ps.dmarcIndeterminate {
		return emailSpoofIndeterminate
	}
	if !hasSPF && !hasDMARC {
		return emailSpoofUnprotected
	}
	if hasSPF && hasDMARC {
		return classifyDMARCPolicy(ps)
	}
	if hasSPF {
		return emailSpoofSPFOnly
	}
	if hasDMARC {
		return emailSpoofDMARCOnly
	}
	return emailSpoofUncertain
}

func classifyDMARCPolicy(ps protocolState) emailSpoofClass {
	switch ps.dmarcPolicy {
	case mapKeyReject:
		// RFC 7489 applies pct= to reject exactly as to quarantine, and
		// pct=0 on reject is a known rollback trick. An unconditional
		// "enforced" here graded zero enforcement as a closed door.
		if ps.dmarcPct >= 100 {
			return emailSpoofReject
		}
		if ps.dmarcPct <= 0 {
			return emailSpoofMonitorOnly
		}
		return emailSpoofRejectPartial
	case mapKeyQuarantine:
		if ps.dmarcPct >= 100 {
			return emailSpoofQuarantineFull
		}
		// pct=0 requests enforcement on 0% of the stream — operationally
		// monitor-only, not "partial": nothing is quarantined, so classing it
		// partial would colour zero enforcement as a guarded door.
		if ps.dmarcPct <= 0 {
			return emailSpoofMonitorOnly
		}
		return emailSpoofQuarantinePartial
	case statusNone:
		return emailSpoofMonitorOnly
	default:
		return emailSpoofUncertain
	}
}

var emailAnswerText = map[emailSpoofClass]string{
	emailSpoofNoMail:            "No — null MX indicates no-mail domain",
	emailSpoofUnprotected:       "Yes — no SPF or DMARC protection",
	emailSpoofReject:            "No — SPF and DMARC reject policy enforced",
	emailSpoofQuarantineFull:    "Partly — DMARC quarantine is enforced at 100%, but quarantined mail is delivered to spam rather than refused",
	emailSpoofQuarantinePartial: "Partly — DMARC quarantine covers only part of the mail, and quarantined mail is delivered to spam rather than refused",
	emailSpoofRejectPartial:     "Partly — DMARC reject covers only part of the mail; covered messages are refused, the remainder is delivered normally",
	emailSpoofMonitorOnly:       "Yes — DMARC requests no enforcement (p=none)",
	emailSpoofSPFOnly:           "Likely — SPF alone cannot prevent spoofing",
	emailSpoofDMARCOnly:         "Partially — DMARC present but no SPF",
	emailSpoofUncertain:         "Uncertain — incomplete configuration",
	emailSpoofIndeterminate:     "Could not verify — a DNS lookup did not complete; re-run before concluding",
}

type emailAnswerDetail struct {
	answer string
	reason string
	color  string
}

var emailAnswerDetails = map[emailSpoofClass]emailAnswerDetail{
	emailSpoofNoMail:            {"No", "null MX indicates no-mail domain", mapKeySuccess},
	emailSpoofUnprotected:       {answerYes, "no SPF or DMARC protection", mapKeyDanger},
	emailSpoofReject:            {"No", "SPF and DMARC reject policy enforced", mapKeySuccess},
	emailSpoofQuarantineFull:    {strPartly, "SPF and DMARC are enforced at p=quarantine, 100% (RFC 7489 §6.3) — receivers accept failing mail and set it aside, so a spoofed message still reaches the mailbox in spam or junk rather than being refused", mapKeySuccess},
	emailSpoofQuarantinePartial: {strPartly, "DMARC quarantine applies to only part of the mail stream (RFC 7489 §6.3), and quarantined mail is delivered to spam rather than refused — the uncovered remainder is delivered normally", mapKeyWarning},
	emailSpoofRejectPartial:     {strPartly, "DMARC reject applies to only part of the mail stream (RFC 7489 §6.3) — covered messages that fail authentication are refused at the gateway, and the uncovered remainder is delivered normally", mapKeyWarning},
	emailSpoofMonitorOnly:       {answerYes, "DMARC requests no enforcement (p=none)", mapKeyDanger},
	emailSpoofSPFOnly:           {strLikely, "SPF alone cannot prevent spoofing", mapKeyDanger},
	emailSpoofDMARCOnly:         {strPartially, "DMARC present but no SPF", mapKeyWarning},
	emailSpoofUncertain:         {"Uncertain", "incomplete configuration", mapKeyWarning},
	emailSpoofIndeterminate:     {"Could not verify", "a DNS lookup did not complete — re-run before concluding", "secondary"},
}

// monitorOnlyShape names the record shape that produced the monitor-only
// verdict. Two different records land in emailSpoofMonitorOnly — p=none, and
// quarantine with pct=0 (enforcement requested on 0% of the stream) — and the
// answer must describe the record actually observed: writing "(p=none)" for a
// quarantine-pct=0 record would assert record content that is not there.
func monitorOnlyShape(ps protocolState) string {
	switch ps.dmarcPolicy {
	case mapKeyQuarantine:
		return "quarantine at pct=0"
	case mapKeyReject:
		return "reject at pct=0"
	}
	return "p=none"
}

func buildEmailAnswer(ps protocolState, hasSPF, hasDMARC bool) string {
	cls := classifyEmailSpoofability(ps, hasSPF, hasDMARC)
	if cls == emailSpoofMonitorOnly {
		return "Yes — DMARC requests no enforcement (" + monitorOnlyShape(ps) + ")"
	}
	if text, ok := emailAnswerText[cls]; ok {
		return text
	}
	return emailAnswerText[emailSpoofUncertain]
}

func buildEmailAnswerStructured(ps protocolState, hasSPF, hasDMARC bool) map[string]string {
	cls := classifyEmailSpoofability(ps, hasSPF, hasDMARC)
	detail, ok := emailAnswerDetails[cls]
	if !ok {
		detail = emailAnswerDetails[emailSpoofUncertain]
	}
	if cls == emailSpoofMonitorOnly {
		// Shape-accurate reason — see monitorOnlyShape.
		detail.reason = "DMARC requests no enforcement (" + monitorOnlyShape(ps) + ")"
	}
	return map[string]string{mapKeyAnswer: detail.answer, mapKeyReason: detail.reason, mapKeyColor: detail.color}
}

// Every branch names the observation behind its label. Five of these six
// previously emitted a label, a colour and an icon with no reason and no
// answer — a predicate with no evidence attached. "Basic" is the one that
// mattered most: it is a judgement about ADEQUACY, and it was being asserted
// without saying what was measured or what remains open.
func buildEmailVerdict(vi verdictInput, verdicts map[string]any) {
	if vi.ps.spfIndeterminate || vi.ps.dmarcIndeterminate {
		verdicts[mapKeyEmailSpoofing] = map[string]any{
			mapKeyLabel:  "Inconclusive",
			mapKeyColor:  "secondary",
			mapKeyIcon:   "question",
			mapKeyAnswer: "Unknown",
			mapKeyReason: "A DNS lookup for SPF or DMARC did not complete, so no conclusion is available. This is not evidence that either record is absent — the measurement failed, and a failed measurement is not a finding.",
		}
		return
	}

	if vi.hasSPF && vi.hasDMARC && (vi.ps.dmarcPolicy == mapKeyReject || vi.ps.dmarcPolicy == mapKeyQuarantine) && vi.ps.dmarcPct >= 100 {
		buildEnforcingEmailVerdict(vi.ps, vi.ds, verdicts)
		return
	}

	if vi.hasSPF && !vi.hasDMARC {
		verdicts[mapKeyEmailSpoofing] = map[string]any{
			mapKeyLabel:  strBasic,
			mapKeyColor:  mapKeyWarning,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: strLikely,
			mapKeyReason: "SPF is published but no DMARC record was found (RFC 7489 §6.3). SPF alone tells a receiver which hosts may send, but nothing about what to do when a message fails — and it does not cover the From: address a reader actually sees, so a spoofed message can still be delivered.",
		}
		return
	}

	if !vi.hasSPF && !vi.hasDMARC {
		verdicts[mapKeyEmailSpoofing] = map[string]any{
			mapKeyLabel:  strExposed,
			mapKeyColor:  mapKeyDanger,
			mapKeyIcon:   iconExclamationTriangle,
			mapKeyAnswer: answerYes,
			mapKeyReason: "Neither SPF (RFC 7208) nor DMARC (RFC 7489) was found. Nothing instructs a receiver to check whether mail claiming this domain is authorised, so anyone can send as this domain and the message will be delivered normally.",
		}
		return
	}

	if vi.hasSPF && vi.hasDMARC {
		verdicts[mapKeyEmailSpoofing] = buildNonEnforcingEmailVerdict(vi.ps)
		return
	}

	verdicts[mapKeyEmailSpoofing] = map[string]any{
		mapKeyLabel:  strExposed,
		mapKeyColor:  mapKeyDanger,
		mapKeyIcon:   iconExclamationTriangle,
		mapKeyAnswer: answerYes,
		mapKeyReason: "The combination of SPF and DMARC records observed does not request any enforcement, so a receiver is not asked to reject or set aside mail that fails authentication.",
	}
}

// buildNonEnforcingEmailVerdict covers SPF + DMARC present but not enforcing:
// p=none, or quarantine below 100%. "Basic" asserts adequacy, so it has to say
// what is actually configured and what that leaves open.
func buildNonEnforcingEmailVerdict(ps protocolState) map[string]any {
	reason := "SPF and DMARC are both published, but the DMARC policy does not request enforcement (RFC 7489 §6.3), so a message failing authentication is delivered normally."
	switch {
	case ps.dmarcPolicy == statusNone:
		reason = "SPF and DMARC are both published, but DMARC is at p=none (RFC 7489 §6.3) — a monitoring policy. Authentication results are reported to the domain owner, and nothing is blocked: a spoofed message that fails is delivered to the inbox exactly as it would be with no DMARC record."
	case ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct > 0 && ps.dmarcPct < 100:
		reason = fmt.Sprintf("SPF and DMARC are both published, and DMARC requests quarantine for %d%% of mail (RFC 7489 §6.3). The remaining %d%% is delivered normally, and quarantined mail is set aside in spam rather than refused — so a spoofed message can still reach the recipient by either route.", ps.dmarcPct, 100-ps.dmarcPct)
	case ps.dmarcPolicy == mapKeyReject && ps.dmarcPct > 0 && ps.dmarcPct < 100:
		reason = fmt.Sprintf("SPF and DMARC are both published, and DMARC requests reject for %d%% of mail (RFC 7489 §6.3) — messages in the covered fraction that fail authentication are refused at the gateway. The remaining %d%% is delivered normally, so a spoofed message can still reach the recipient through the uncovered share.", ps.dmarcPct, 100-ps.dmarcPct)
	case (ps.dmarcPolicy == mapKeyReject || ps.dmarcPolicy == mapKeyQuarantine) && ps.dmarcPct <= 0:
		reason = fmt.Sprintf("SPF and DMARC are both published, but the %s policy carries pct=0 (RFC 7489 §6.3) — enforcement applies to 0%% of the mail stream, so nothing is blocked: a spoofed message that fails authentication is delivered exactly as it would be under p=none.", ps.dmarcPolicy)
	}
	return map[string]any{
		mapKeyLabel:  strBasic,
		mapKeyColor:  mapKeyWarning,
		mapKeyIcon:   iconShieldAlt,
		mapKeyAnswer: strLikely,
		mapKeyReason: reason,
	}
}

// buildEnforcingEmailVerdict answers "can this domain be impersonated by
// email?" for the two fully-enforcing DMARC policies. They are NOT the same
// answer, and this branch used to collapse them.
//
// It previously emitted label/colour/icon and nothing else — no answer, no
// reason — while every other builder in this file supplies both. The branch
// making the strongest claim was the only one offering no observation to back
// it. It also took ps and ds and read neither, so it could not have been
// conditioned on anything.
//
// p=reject asks receivers to REFUSE unauthenticated mail at the gateway: it
// does not reach the mailbox. p=quarantine at 100% asks receivers to ACCEPT it
// and set it aside — it lands in spam or junk, where a user can still open it.
// Both are strong, deliberate postures and both stay green; the colour is not
// the thing that was wrong. The predicate was.
//
// buildDNSVerdict's AD-flag branch is the house model for this: it withholds
// "Protected" when the confirming observation was not made.
func buildEnforcingEmailVerdict(ps protocolState, ds DKIMState, verdicts map[string]any) {
	if ps.dmarcPolicy == mapKeyQuarantine {
		verdicts[mapKeyEmailSpoofing] = map[string]any{
			mapKeyLabel:  strQuarantined,
			mapKeyColor:  mapKeySuccess,
			mapKeyIcon:   iconShieldHalved,
			mapKeyAnswer: strUnlikely,
			mapKeyReason: "SPF and DMARC are enforced at p=quarantine, 100% (RFC 7489 §6.3). Quarantine asks receivers to accept failing mail and set it aside rather than refuse it, so a spoofed message is still delivered — typically to a spam or junk folder — where a recipient can open it. Some operators choose quarantine deliberately to retain that message-level visibility; p=reject is the posture that stops the message reaching the mailbox at all.",
		}
		return
	}
	verdicts[mapKeyEmailSpoofing] = map[string]any{
		mapKeyLabel:  strProtected,
		mapKeyColor:  mapKeySuccess,
		mapKeyIcon:   iconShieldAlt,
		mapKeyAnswer: strUnlikely,
		mapKeyReason: "SPF and DMARC are enforced at p=reject, 100% (RFC 7489 §6.3) — receivers are asked to refuse unauthenticated mail at the gateway, so a spoofed message is rejected rather than delivered.",
	}
}

func buildBrandVerdict(ps protocolState, verdicts map[string]any) {
	if ps.dmarcMissing {
		verdicts[mapKeyBrandImpersonation] = map[string]any{
			mapKeyLabel:  strExposed,
			mapKeyColor:  mapKeyDanger,
			mapKeyIcon:   iconExclamationTriangle,
			mapKeyAnswer: answerYes,
			mapKeyReason: "No DMARC policy (RFC 7489) — attackers can send email appearing to be from this domain with no sender-authentication barrier",
		}
		return
	}

	// pct=0 on either policy enforces nothing — the brand verdict must not
	// assert reject/quarantine protection for a policy that applies to 0% of
	// the mail stream.
	switch {
	case ps.dmarcPolicy == mapKeyReject && ps.dmarcPct > 0:
		verdicts[mapKeyBrandImpersonation] = buildBrandRejectVerdict(ps)
	case ps.dmarcPolicy == mapKeyQuarantine && ps.dmarcPct > 0:
		verdicts[mapKeyBrandImpersonation] = buildBrandQuarantineVerdict(ps)
	default:
		verdicts[mapKeyBrandImpersonation] = buildBrandWeakVerdict(ps)
	}
}

// bimiGapPhrase describes the BIMI shortfall in a brand-impersonation reason.
// An indeterminate lookup must read as "could not verify", never a confirmed
// "no BIMI" — a transient DNS failure is not evidence the record is absent.
func bimiGapPhrase(ps protocolState) string {
	if ps.bimiIndeterminate {
		return "BIMI could not be verified (a DNS lookup did not complete — re-run before concluding)"
	}
	return "no BIMI brand verification"
}

// caaGapPhrase describes the CAA shortfall in a brand-impersonation reason,
// with the same Zero-Fabrication tri-state discipline as bimiGapPhrase.
func caaGapPhrase(ps protocolState) string {
	if ps.caaIndeterminate {
		return "CAA could not be verified (a DNS lookup did not complete — re-run before concluding)"
	}
	return "no CAA certificate restriction (RFC 8659)"
}

// caaSuggestionClause returns a trailing "; adding CAA …" recommendation only
// when CAA is authoritatively absent. When the lookup is indeterminate we must
// not suggest adding a record that may already exist — instead note it could
// not be verified.
func caaSuggestionClause(ps protocolState) string {
	if ps.caaIndeterminate {
		return "; CAA could not be verified (a DNS lookup did not complete) — re-run before concluding it is absent"
	}
	return "; adding CAA records (RFC 8659) would further restrict certificate issuance for lookalike domains"
}

func buildBrandRejectVerdict(ps protocolState) map[string]any {
	if ps.bimiOK && ps.caaOK {
		return map[string]any{
			mapKeyLabel:  strProtected,
			mapKeyColor:  mapKeySuccess,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: "No",
			mapKeyReason: "DMARC reject policy enforced (RFC 7489 §6.3), BIMI brand verification active (BIMI Spec), and certificate issuance restricted by CAA (RFC 8659 §4) — all three brand-faking vectors addressed",
		}
	}
	if ps.bimiOK {
		reason := "DMARC reject policy blocks email spoofing (RFC 7489 §6.3) and BIMI with VMC provides verified brand identity in inboxes — email-based brand faking is effectively blocked"
		if !ps.caaOK {
			reason += caaSuggestionClause(ps)
		}
		return map[string]any{
			mapKeyLabel:  "Well Protected",
			mapKeyColor:  mapKeySuccess,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: strUnlikely,
			mapKeyReason: reason,
		}
	}
	if ps.caaOK {
		return map[string]any{
			mapKeyLabel:  "Mostly Protected",
			mapKeyColor:  statusInfoPosture,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: strPossible,
			mapKeyReason: "DMARC reject policy blocks email spoofing (RFC 7489 §6.3) and CAA restricts certificate issuance (RFC 8659 §4), but " + bimiGapPhrase(ps) + " — lookalike domains display identically in inboxes without visual proof of authenticity",
		}
	}
	return map[string]any{
		mapKeyLabel:  "Partially Protected",
		mapKeyColor:  mapKeyWarning,
		mapKeyIcon:   iconExclamationTriangle,
		mapKeyAnswer: strPossible,
		mapKeyReason: "DMARC reject policy blocks email spoofing (RFC 7489 §6.3), but " + bimiGapPhrase(ps) + " and " + caaGapPhrase(ps) + " — visual impersonation via lookalike domains and unrestricted certificate issuance remain open vectors",
	}
}

func buildBrandQuarantineVerdict(ps protocolState) map[string]any {
	if ps.bimiOK && ps.caaOK {
		return map[string]any{
			mapKeyLabel:  "Well Protected",
			mapKeyColor:  mapKeySuccess,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: strUnlikely,
			mapKeyReason: "DMARC quarantine enforced (RFC 7489 §6.3) with BIMI brand verification (VMC-validated logo in inboxes) and CAA certificate restriction (RFC 8659 §4) — all three brand-faking vectors addressed; upgrade to p=reject to block spoofed mail outright instead of flagging",
		}
	}
	if ps.bimiOK {
		reason := "DMARC quarantine flags spoofed mail (RFC 7489 §6.3) and BIMI with VMC provides verified brand identity in inboxes; upgrade to p=reject to block spoofed mail outright"
		if !ps.caaOK {
			reason += caaSuggestionClause(ps)
		}
		return map[string]any{
			mapKeyLabel:  "Mostly Protected",
			mapKeyColor:  statusInfoPosture,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: strPossible,
			mapKeyReason: reason,
		}
	}
	if ps.caaOK {
		return map[string]any{
			mapKeyLabel:  "Partially Protected",
			mapKeyColor:  mapKeyWarning,
			mapKeyIcon:   iconExclamationTriangle,
			mapKeyAnswer: strLikely,
			mapKeyReason: "DMARC quarantine flags but does not reject spoofed mail (RFC 7489 §6.3), and " + bimiGapPhrase(ps) + " — lookalike domains display identically in inboxes; CAA restricts certificate issuance (RFC 8659 §4) but visual brand faking remains open",
		}
	}
	return map[string]any{
		mapKeyLabel:  strBasic,
		mapKeyColor:  mapKeyWarning,
		mapKeyIcon:   iconExclamationTriangle,
		mapKeyAnswer: strLikely,
		mapKeyReason: "DMARC quarantine flags but does not reject spoofed mail (RFC 7489 §6.3) — " + bimiGapPhrase(ps) + " and " + caaGapPhrase(ps) + " leave brand impersonation largely unaddressed",
	}
}

func buildBrandWeakVerdict(ps protocolState) map[string]any {
	reason := "DMARC policy is not set to reject (RFC 7489 §6.3) — partial protection only"
	if ps.dmarcPolicy == statusNone {
		reason = "DMARC is monitor-only p=none (RFC 7489 §6.3) — spoofed mail is not blocked, brand faking is trivial"
	}
	return map[string]any{
		mapKeyLabel:  strBasic,
		mapKeyColor:  mapKeyWarning,
		mapKeyIcon:   iconExclamationTriangle,
		mapKeyAnswer: strLikely,
		mapKeyReason: reason,
	}
}

func buildDNSVerdict(ps protocolState, verdicts map[string]any) {
	if ps.dnssecOK {
		if ps.dnssecADValidated {
			verdicts[mapKeyDnsTampering] = map[string]any{
				mapKeyLabel:  strProtected,
				mapKeyColor:  mapKeySuccess,
				mapKeyIcon:   iconShieldAlt,
				mapKeyAnswer: "No",
				mapKeyReason: "DNSSEC signed; a validating resolver confirmed the cryptographic chain of trust via the AD flag (RFC 4035 §3.2.3)",
			}
		} else {
			// Signed (DNSKEY+DS present) but the resolver did not set the AD flag, so
			// we did NOT observe chain-of-trust validation on our path. Do not claim
			// full protection — a non-validating resolver path would not enforce it.
			verdicts[mapKeyDnsTampering] = map[string]any{
				mapKeyLabel:  strPartially,
				mapKeyColor:  mapKeyWarning,
				mapKeyIcon:   iconShieldHalved,
				mapKeyAnswer: strPossible,
				mapKeyReason: "DNSSEC signed (DNSKEY + DS present), but chain-of-trust validation was not confirmed on our resolver path (AD flag unset, RFC 4035 §3.2.3) — protection depends on the client using a validating resolver",
			}
		}
	} else if ps.dnssecBroken {
		verdicts[mapKeyDnsTampering] = map[string]any{
			mapKeyLabel:  strExposed,
			mapKeyColor:  mapKeyDanger,
			mapKeyIcon:   iconExclamationTriangle,
			mapKeyAnswer: answerYes,
			mapKeyReason: "DNSSEC validation is failing, DNS responses cannot be trusted",
		}
	} else if ps.dnssecIndeterminate {
		verdicts[mapKeyDnsTampering] = map[string]any{
			mapKeyLabel:  "Could Not Verify",
			mapKeyColor:  mapKeySecondary,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: "Unknown",
			mapKeyReason: "DNSSEC could not be verified — the DNSKEY/DS lookup did not complete (transient resolver failure). This is not evidence the zone is unsigned (RFC 4035); re-run to confirm.",
		}
	} else {
		verdicts[mapKeyDnsTampering] = map[string]any{
			mapKeyLabel:  "Not Configured",
			mapKeyColor:  mapKeySecondary,
			mapKeyIcon:   iconShieldAlt,
			mapKeyAnswer: strPossible,
			mapKeyReason: "DNSSEC is not deployed, DNS responses are not cryptographically verified",
		}
	}
}

func buildTransportVerdict(ps protocolState, verdicts map[string]any) {
	if ps.mtaStsOK && ps.daneOK {
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  "Fully Protected",
			mapKeyColor:  mapKeySuccess,
			mapKeyAnswer: answerYes,
			mapKeyReason: "Both MTA-STS and DANE enforce encrypted mail delivery",
		}
	} else if ps.mtaStsOK {
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  strProtected,
			mapKeyColor:  mapKeySuccess,
			mapKeyAnswer: answerYes,
			mapKeyReason: "MTA-STS enforces TLS for all inbound mail delivery",
		}
	} else if ps.daneOK {
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  strProtected,
			mapKeyColor:  mapKeySuccess,
			mapKeyAnswer: answerYes,
			mapKeyReason: "DANE/TLSA provides cryptographic transport verification",
		}
	} else if ps.mtaStsIndeterminate {
		// MTA-STS lookup did not complete authoritatively. We cannot fall through to a
		// "TLS-RPT monitoring only / not enforced" verdict — an enforcing MTA-STS policy
		// may well exist. Reporting absence here would fabricate a missing control.
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  "Could Not Verify",
			mapKeyColor:  mapKeySecondary,
			mapKeyAnswer: "Unknown",
			mapKeyReason: "Mail transport security could not be verified — the MTA-STS DNS lookup did not complete; a TLS-RPT record alone does not enforce TLS, so this is not evidence enforcement is absent. Re-run before concluding transport encryption is unenforced",
		}
	} else if ps.tlsrptOK {
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  "Monitoring",
			mapKeyColor:  statusInfoPosture,
			mapKeyAnswer: strPartially,
			mapKeyReason: "TLS reporting is configured but no transport enforcement policy is active",
		}
	} else if ps.tlsrptIndeterminate {
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  "Could Not Verify",
			mapKeyColor:  mapKeySecondary,
			mapKeyAnswer: "Unknown",
			mapKeyReason: "Mail transport security could not be verified — the TLS-RPT DNS lookup did not complete; re-run before concluding transport reporting is absent",
		}
	} else {
		verdicts[mapKeyTransport] = map[string]any{
			mapKeyLabel:  "Not Enforced",
			mapKeyColor:  mapKeySecondary,
			mapKeyAnswer: "No",
			mapKeyReason: "No MTA-STS or DANE — mail transport encryption is opportunistic only",
		}
	}
}

func getNumericValue(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

func buildAISurfaceVerdicts(results, verdicts map[string]any) {
	aiSurface, ok := results["ai_surface"].(map[string]any)
	if !ok {
		return
	}

	llmsTxt, _ := aiSurface["llms_txt"].(map[string]any)
	robotsTxt, _ := aiSurface["robots_txt"].(map[string]any)
	poisoning, _ := aiSurface["poisoning"].(map[string]any)
	hiddenPrompts, _ := aiSurface["hidden_prompts"].(map[string]any)

	buildLlmsTxtVerdict(llmsTxt, verdicts)
	buildRobotsTxtVerdict(robotsTxt, verdicts)
	buildPoisoningVerdict(poisoning, verdicts)
	buildHiddenPromptsVerdict(hiddenPrompts, verdicts)
}

func buildLlmsTxtVerdict(llmsTxt, verdicts map[string]any) {
	if llmsTxt == nil {
		return
	}
	found, _ := llmsTxt["found"].(bool)
	fullFound, _ := llmsTxt["full_found"].(bool)
	if found && fullFound {
		verdicts[mapKeyAiLlmsTxt] = map[string]any{
			mapKeyAnswer: answerYes,
			mapKeyColor:  mapKeySuccess,
			mapKeyReason: "llms.txt and llms-full.txt published — AI models receive structured context about this domain",
		}
	} else if found {
		verdicts[mapKeyAiLlmsTxt] = map[string]any{
			mapKeyAnswer: answerYes,
			mapKeyColor:  mapKeySuccess,
			mapKeyReason: "llms.txt published — AI models receive structured context about this domain",
		}
	} else {
		verdicts[mapKeyAiLlmsTxt] = map[string]any{
			mapKeyAnswer: "No",
			mapKeyColor:  mapKeySecondary,
			mapKeyReason: "No llms.txt file detected — AI models have no structured instructions for this domain",
		}
	}
}

func buildRobotsTxtVerdict(robotsTxt, verdicts map[string]any) {
	if robotsTxt == nil {
		return
	}
	found, _ := robotsTxt["found"].(bool)
	blocksAI, _ := robotsTxt["blocks_ai_crawlers"].(bool)
	if found && blocksAI {
		verdicts[mapKeyAiCrawlerGovernance] = map[string]any{
			mapKeyAnswer: answerYes,
			mapKeyColor:  mapKeySuccess,
			mapKeyReason: "robots.txt actively blocks AI crawlers from scraping site content",
		}
	} else if found {
		verdicts[mapKeyAiCrawlerGovernance] = map[string]any{
			mapKeyAnswer: "No",
			mapKeyColor:  mapKeyWarning,
			mapKeyReason: "robots.txt present but does not block AI crawlers — content may be freely scraped",
		}
	} else {
		verdicts[mapKeyAiCrawlerGovernance] = map[string]any{
			mapKeyAnswer: "No",
			mapKeyColor:  mapKeySecondary,
			mapKeyReason: "No robots.txt found — AI crawlers have unrestricted access",
		}
	}
}

func buildPoisoningVerdict(poisoning, verdicts map[string]any) {
	if poisoning == nil {
		return
	}
	iocCount := getNumericValue(poisoning, "ioc_count")
	if iocCount > 0 {
		verdicts["ai_poisoning"] = map[string]any{
			mapKeyAnswer: answerYes,
			mapKeyColor:  mapKeyDanger,
			mapKeyReason: fmt.Sprintf("%.0f indicator(s) of AI recommendation manipulation detected on homepage", iocCount),
		}
	} else {
		verdicts["ai_poisoning"] = map[string]any{
			mapKeyAnswer: "No",
			mapKeyColor:  mapKeySuccess,
			mapKeyReason: "No indicators of AI recommendation manipulation found",
		}
	}
}

func buildHiddenPromptsVerdict(hiddenPrompts, verdicts map[string]any) {
	if hiddenPrompts == nil {
		return
	}
	artifactCount := getNumericValue(hiddenPrompts, "artifact_count")
	if artifactCount > 0 {
		verdicts["ai_hidden_prompts"] = map[string]any{
			mapKeyAnswer: answerYes,
			mapKeyColor:  mapKeyDanger,
			mapKeyReason: fmt.Sprintf("%.0f hidden prompt-like artifact(s) detected in page source", artifactCount),
		}
	} else {
		verdicts["ai_hidden_prompts"] = map[string]any{
			mapKeyAnswer: "No",
			mapKeyColor:  mapKeySuccess,
			mapKeyReason: "No hidden prompt artifacts found in page source",
		}
	}
}

// Maximum points each scored protocol can contribute. They sum to
// scoreDenominator (100), which is the denominator when every protocol is
// measurable. When a protocol's measurement is indeterminate its weight is
// removed from BOTH the earned points and the denominator (available-denominator
// normalization) so an unmeasurable protocol can neither inflate nor depress the
// posture score (judgment and analytic confidence are separate declared axes).
const (
	scoreDenominator = 100
	weightSPF        = 20
	weightDMARC      = 30
	weightDNSSEC     = 10
	weightDANE       = 5
	weightMTASTS     = 5
	weightTLSRPT     = 5
	weightCAA        = 5
	weightBIMI       = 5
)

func computeInternalScore(ps protocolState, ds DKIMState) int {
	rawScore := computeSPFScore(ps) + computeDMARCScore(ps) + computeDKIMScore(ds) + computeAuxScore(ps)

	attainable := scoreDenominator
	if ps.spfIndeterminate {
		attainable -= weightSPF
	}
	if ps.dmarcIndeterminate {
		attainable -= weightDMARC
	}
	// Aux/crypto protocols: a transient lookup failure (dnssec/dane/mta-sts/
	// tls-rpt/caa/bimi) is neither present nor absent, so remove its weight from
	// the denominator too. Otherwise the 0 raw points computeAuxScore contributes
	// would read as an absence penalty — fabricating a finding from a timeout.
	if ps.dnssecIndeterminate {
		attainable -= weightDNSSEC
	}
	if ps.daneIndeterminate {
		attainable -= weightDANE
	}
	if ps.mtaStsIndeterminate {
		attainable -= weightMTASTS
	}
	if ps.tlsrptIndeterminate {
		attainable -= weightTLSRPT
	}
	if ps.caaIndeterminate {
		attainable -= weightCAA
	}
	if ps.bimiIndeterminate {
		attainable -= weightBIMI
	}
	if attainable <= 0 {
		// Nothing measurable was scored; refuse to fabricate a point estimate.
		return 0
	}

	// Integer round-half-up of rawScore/attainable*100. When nothing is
	// indeterminate, attainable==100 and this is an exact identity (no score
	// movement for the common path).
	score := (rawScore*100 + attainable/2) / attainable
	if score > 100 {
		score = 100
	}
	return score
}

func computeSPFScore(ps protocolState) int {
	if ps.spfIndeterminate {
		// Transient lookup failure — neither configured nor absent. Contribute 0
		// raw points; computeInternalScore also removes SPF's weight from the
		// denominator so this 0 is neutral, never an absence penalty (RFC 7208).
		return 0
	}
	if ps.spfMissing {
		return 0
	}
	if ps.spfDangerous {
		return 5
	}
	if ps.spfHardFail {
		return 20
	}
	return 15
}

func computeDMARCScore(ps protocolState) int {
	if ps.dmarcIndeterminate {
		// Transient lookup failure — neither configured nor absent. Contribute 0
		// raw points; computeInternalScore also removes DMARC's weight from the
		// denominator so this 0 is neutral, never an absence penalty (RFC 7489).
		return 0
	}
	if ps.dmarcMissing {
		return 0
	}
	switch ps.dmarcPolicy {
	case mapKeyReject:
		return 30
	case mapKeyQuarantine:
		if ps.dmarcPct >= 100 {
			return 25
		}
		return 20
	case statusNone:
		if ps.dmarcHasRua {
			return 10
		}
		return 5
	}
	return 10
}

func computeDKIMScore(ds DKIMState) int {
	switch ds {
	case DKIMSuccess:
		return 15
	case DKIMProviderInferred:
		return 12
	case DKIMThirdPartyOnly:
		return 8
	case DKIMWeakKeysOnly:
		return 5
	case DKIMNoMailDomain:
		return 15
	}
	return 0
}

func computeAuxScore(ps protocolState) int {
	score := 0
	if ps.dnssecOK {
		score += weightDNSSEC
	}
	if ps.daneOK {
		score += weightDANE
	}
	if ps.mtaStsOK {
		score += weightMTASTS
	}
	if ps.tlsrptOK {
		score += weightTLSRPT
	}
	if ps.caaOK {
		score += weightCAA
	}
	if ps.bimiOK {
		score += weightBIMI
	}
	return score
}
