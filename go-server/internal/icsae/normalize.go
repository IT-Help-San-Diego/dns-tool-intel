// dns-tool:scrutiny science
package icsae

// Observations holds the derived tri-state observation codes the catalog's
// controls are evaluated against, mirroring the schema-v9 contract of
// dns-eval/Mappings/normalize_input.py:
//
//	true  -> measured, condition holds
//	false -> measured, condition does NOT hold
//	nil   -> NOT measured (section absent, status n/a/error/info, ambiguous)
//
// A missing or indeterminate measurement is NEVER equivalent to false;
// evaluateObservations grades nil as not_measured, excluded from the
// denominator.
type Observations map[string]*bool

// tb pins a measured boolean observation.
func tb(v bool) *bool { return &v }

// deriveObservations ports dns-eval/Mappings/normalize_input.py (tri-state,
// schema v9). It reads the analyzer results map (the same object the Python
// engine sees as full_results) and derives the observation codes. Python
// semantics are preserved exactly: key presence is distinguished from value
// (Python `"k" in m` vs `m.get(k)`), a JSON null behaves like a missing key
// (both are None to Python), and a measured non-bool value collapses to nil
// because evaluate.py's `v is True` / `v is False` checks treat it as neither.
func deriveObservations(fr map[string]any) Observations {
	dnssec := getMap(fr, "dnssec_analysis")
	spf := getMap(fr, "spf_analysis")
	dmarc := getMap(fr, "dmarc_analysis")
	mail := getMap(fr, "mail_posture")
	tlsrpt := getMap(fr, "tlsrpt_analysis")
	mtaSts := getMap(fr, "mta_sts_analysis")
	caa := getMap(fr, "caa_analysis")
	dkim := getMap(fr, "dkim_analysis")
	dane := getMap(fr, "dane_analysis")
	bimi := getMap(fr, "bimi_analysis")
	securityTxt := getMap(fr, "security_txt")
	dangling := getMap(fr, "dangling_dns")
	delegation := getMap(fr, "delegation_consistency")
	secretExp := getMap(fr, "secret_exposure")
	httpsSvcb := getMap(fr, "https_svcb")
	cdsCdnskey := getMap(fr, "cds_cdnskey")

	// DNSSEC: chain is the semantic field; ad is the resolver flag.
	chain := triStr(dnssec["chain_of_trust"])
	dnssecStatus := triStr(dnssec["status"])
	var dnssecValid *bool
	switch {
	case (chain == "complete" || chain == "inherited") && dnssecStatus == "success" && dnssec["ad_flag"] == true:
		dnssecValid = tb(true)
	case chain == "none" || chain == "broken":
		dnssecValid = tb(false)
	}
	dnssecChainValid := dnssecValid // same semantics per the registry

	var rollover *bool
	if hasAnyKey(cdsCdnskey, "has_cds", "has_cdnskey", "automation") {
		rollover = tb(pyTruthy(cdsCdnskey["has_cds"]) || pyTruthy(cdsCdnskey["has_cdnskey"]) ||
			getString(cdsCdnskey, "automation") == "active")
	}

	var nullMX *bool
	if v, present := fr["has_null_mx"]; present {
		if b, isBool := v.(bool); isBool {
			nullMX = tb(b)
		}
	}

	spfMech := triStr(spf["all_mechanism"])
	var spfHard, spfSoft *bool
	if spfMech != "" {
		spfHard = tb(spfMech == "-all")
		spfSoft = tb(spfMech == "~all")
	} else if getString(spf, "status") == "missing" {
		spfHard, spfSoft = tb(false), tb(false)
	}

	dmarcPol := triStr(dmarc["policy"])
	var dmarcReject, dmarcEnforcing *bool
	if dmarcPol != "" {
		dmarcReject = tb(dmarcPol == "reject")
		dmarcEnforcing = tb(dmarcPol == "reject" || dmarcPol == "quarantine")
	} else if getString(dmarc, "status") == "missing" {
		dmarcReject, dmarcEnforcing = tb(false), tb(false)
	}

	var spfSoftfailDmarc *bool
	switch {
	case spfSoft != nil && !*spfSoft:
		spfSoftfailDmarc = tb(false)
	case spfSoft != nil && *spfSoft && dmarcEnforcing != nil && *dmarcEnforcing:
		spfSoftfailDmarc = tb(true)
	case spfSoft != nil && *spfSoft && dmarcEnforcing != nil && !*dmarcEnforcing:
		spfSoftfailDmarc = tb(false)
	}

	// no-mail / mail domain: any true signal -> true; any measured signal,
	// none true -> false; nothing measured -> nil. A measured non-bool signal
	// counts toward "measured" (Python `s is not None`) but never toward true.
	s1 := fr["is_no_mail_domain"]
	var s2 any
	if _, present := mail["verdict"]; present {
		s2 = getString(mail, "verdict") == "no_mail"
	}
	s3 := mail["is_no_mail"]
	var noMail *bool
	anyTrueSig, anyMeasured := false, false
	for _, s := range []any{s1, s2, s3} {
		if s == true {
			anyTrueSig = true
		}
		if s != nil {
			anyMeasured = true
		}
	}
	switch {
	case anyTrueSig:
		noMail = tb(true)
	case anyMeasured:
		noMail = tb(false)
	}
	var mailDomain *bool
	if noMail != nil {
		mailDomain = tb(!*noMail)
	}

	tlsRpt := triStatus(tlsrpt)

	// MTA-STS: an enforce/testing mode is a measured policy; status "warning"
	// is the producer's "No MTA-STS record found" = measured ABSENCE -> false,
	// never present.
	var mtaObs *bool
	if mode := getString(mtaSts, "mode"); mode == "enforce" || mode == "testing" {
		mtaObs = tb(true)
	} else {
		mtaObs = triStatus(mtaSts)
	}

	var caaPresent *bool
	if caa["status"] == "success" && hasNonEmptyList(caa, "records") {
		caaPresent = tb(true)
	} else if caa["status"] == "warning" {
		caaPresent = tb(false)
	}

	var dkimFound *bool
	if b, isBool := dkim["primary_has_dkim"].(bool); isBool {
		dkimFound = tb(b)
	} else if getString(dkim, "status") == "missing" {
		dkimFound = tb(false)
	}

	var danePresent *bool
	if b, isBool := dane["has_dane"].(bool); isBool {
		danePresent = tb(b)
	}

	var bimiValid *bool
	switch bimi["status"] {
	case "success":
		bimiValid = tb(bimi["logo_valid"] == true)
	case "warning", "missing":
		bimiValid = tb(false)
	}

	var secTxt *bool
	if b, isBool := securityTxt["found"].(bool); isBool {
		secTxt = tb(b && !pyTruthy(securityTxt["expired"]))
	} else {
		switch securityTxt["status"] {
		case "missing", "warning":
			secTxt = tb(false)
		}
	}

	var noDangling *bool
	if dangling["status"] == "success" {
		if n, isInt := pyInt(dangling["dangling_count"]); isInt {
			noDangling = tb(n == 0)
		}
	} else if dangling["status"] == "warning" {
		noDangling = tb(false)
	}

	var delegationOK *bool
	switch delegation["status"] {
	case "success":
		delegationOK = tb(true)
	case "warning", "failure":
		delegationOK = tb(false)
	}

	var noSecrets *bool
	if secretExp["status"] == "clear" {
		if n, isInt := pyInt(secretExp["finding_count"]); isInt {
			noSecrets = tb(n == 0)
		}
	} else if secretExp["status"] == "found" || secretExp["status"] == "warning" {
		noSecrets = tb(false)
	}

	var svcb *bool
	if hasAnyKey(httpsSvcb, "has_https", "has_svcb") {
		svcb = tb(pyTruthy(httpsSvcb["has_https"]) || pyTruthy(httpsSvcb["has_svcb"]))
	} else {
		switch httpsSvcb["status"] {
		case "absent", "warning", "missing":
			svcb = tb(false)
		}
	}

	return Observations{
		"DNSSEC_VALID":            dnssecValid,
		"DNSSEC_CHAIN_VALID":      dnssecChainValid,
		"DNSSEC_ROLLOVER_READY":   rollover,
		"NULL_MX":                 nullMX,
		"SPF_HARD_FAIL":           spfHard,
		"SPF_SOFTFAIL_WITH_DMARC": spfSoftfailDmarc,
		"DMARC_REJECT":            dmarcReject,
		"DMARC_ENFORCING":         dmarcEnforcing,
		"NO_MAIL_DOMAIN":          noMail,
		"MAIL_DOMAIN":             mailDomain,
		"TLS_RPT":                 tlsRpt,
		"MTA_STS_DNS":             mtaObs,
		"CAA_PRESENT":             caaPresent,
		"DKIM_FOUND":              dkimFound,
		"DANE_PRESENT":            danePresent,
		"BIMI_VALID":              bimiValid,
		"SECURITY_TXT_FOUND":      secTxt,
		"NO_DANGLING_DNS":         noDangling,
		"DELEGATION_OK":           delegationOK,
		"NO_SECRETS_EXPOSED":      noSecrets,
		"HTTPS_SVCB_PRESENT":      svcb,
	}
}

// triStatus mirrors normalize_input.py tri_status with its default states:
// status "success" -> measured true, "warning" -> measured false, anything
// else (missing section included) -> nil, not measured.
func triStatus(section map[string]any) *bool {
	switch section["status"] {
	case "success":
		return tb(true)
	case "warning":
		return tb(false)
	}
	return nil
}
