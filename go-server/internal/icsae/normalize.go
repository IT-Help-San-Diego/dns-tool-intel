package icsae

// Observations holds the derived boolean observation codes that the catalog's
// controls are evaluated against.
type Observations map[string]bool

// deriveObservations ports dns-eval/Mappings/normalize_input.py. It reads the
// analyzer results map (which is the same object the Python engine sees as
// full_results) and derives the observation codes. Python defaults are preserved
// exactly: dangling_count and finding_count default to 1 (so a missing count is
// treated as "not clean"), and security_txt.expired defaults to true.
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

        isNoMail := getBoolDefault(fr, "is_no_mail_domain", false) ||
                getString(mail, "verdict") == "no_mail" ||
                getBoolDefault(mail, "is_no_mail", false)
        isMail := !isNoMail

        spfMech := getString(spf, "all_mechanism")
        spfSoftfail := spfMech == "~all"
        spfHardfail := spfMech == "-all"

        dmarcPolicy := getString(dmarc, "policy")
        dmarcEnforcing := dmarcPolicy == "reject" || dmarcPolicy == "quarantine"
        dmarcReject := dmarcPolicy == "reject"

        dnssecAd := getBoolDefault(dnssec, "ad_flag", false)
        dnssecChain := getString(dnssec, "chain_of_trust")
        dnssecChainValid := dnssecAd && (dnssecChain == "complete" || dnssecChain == "inherited")

        dnssecRolloverReady := getBoolDefault(cdsCdnskey, "has_cds", false) ||
                getBoolDefault(cdsCdnskey, "has_cdnskey", false) ||
                getString(cdsCdnskey, "automation") == "active"

        mtaStsStatus := getString(mtaSts, "status")
        dkimStatus := getString(dkim, "status")

        return Observations{
                "DNSSEC_VALID":            getString(dnssec, "status") == "success" && dnssecAd,
                "DNSSEC_CHAIN_VALID":      dnssecChainValid,
                "DNSSEC_ROLLOVER_READY":   dnssecRolloverReady,
                "NULL_MX":                 getBoolDefault(fr, "has_null_mx", false),
                "SPF_HARD_FAIL":           spfHardfail,
                "SPF_SOFTFAIL_WITH_DMARC": spfSoftfail && dmarcEnforcing,
                "DMARC_REJECT":            dmarcReject,
                "DMARC_ENFORCING":         dmarcEnforcing,
                "NO_MAIL_DOMAIN":          isNoMail,
                "MAIL_DOMAIN":             isMail,
                "TLS_RPT":                 getString(tlsrpt, "status") == "success",
                "MTA_STS_DNS":             mtaStsStatus == "success" || mtaStsStatus == "warning",
                "CAA_PRESENT":             getString(caa, "status") == "success" && hasNonEmptyList(caa, "records"),
                "DKIM_FOUND":              (dkimStatus == "success" || dkimStatus == "warning") && getBoolDefault(dkim, "primary_has_dkim", false),
                "DANE_PRESENT":            getBoolDefault(dane, "has_dane", false),
                "BIMI_VALID":              getString(bimi, "status") == "success" && getBoolDefault(bimi, "logo_valid", false),
                "SECURITY_TXT_FOUND":      getBoolDefault(securityTxt, "found", false) && !getBoolDefault(securityTxt, "expired", true),
                "NO_DANGLING_DNS":         getString(dangling, "status") == "success" && getFloatDefault(dangling, "dangling_count", 1) == 0,
                "DELEGATION_OK":           getString(delegation, "status") == "success",
                "NO_SECRETS_EXPOSED":      getString(secretExp, "status") == "clear" && getFloatDefault(secretExp, "finding_count", 1) == 0,
                "HTTPS_SVCB_PRESENT":      getBoolDefault(httpsSvcb, "has_https", false) || getBoolDefault(httpsSvcb, "has_svcb", false),
        }
}
