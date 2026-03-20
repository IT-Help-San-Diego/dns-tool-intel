import json
import glob
import os

files = glob.glob("Inputs/dns-intelligence-*.json")
if not files:
    raise FileNotFoundError("Place DNS JSON into Inputs/ before running.")

SOURCE = max(files, key=os.path.getmtime)
DEST = "Mappings/normalized-from-dnstool.json"

with open(SOURCE, "r") as f:
    raw = json.load(f)

fr = raw.get("full_results", {})
domain = raw.get("domain", "unknown")

dnssec = fr.get("dnssec_analysis", {})
spf = fr.get("spf_analysis", {})
dmarc = fr.get("dmarc_analysis", {})
mail = fr.get("mail_posture", {})
tlsrpt = fr.get("tlsrpt_analysis", {})
mta_sts = fr.get("mta_sts_analysis", {})
caa = fr.get("caa_analysis", {})
dkim = fr.get("dkim_analysis", {})
dane = fr.get("dane_analysis", {})
bimi = fr.get("bimi_analysis", {})
security_txt = fr.get("security_txt", {})
dangling = fr.get("dangling_dns", {})
delegation = fr.get("delegation_consistency", {})
secret_exp = fr.get("secret_exposure", {})
https_svcb = fr.get("https_svcb", {})
cds_cdnskey = fr.get("cds_cdnskey", {})
smtp = fr.get("smtp_transport", {})
posture = fr.get("posture", {})
calibrated = fr.get("calibrated_confidence", {})

is_no_mail = fr.get("is_no_mail_domain", False) or mail.get("verdict") == "no_mail" or mail.get("is_no_mail", False)
is_mail = not is_no_mail

normalized = {
    "source_file": os.path.basename(SOURCE),
    "domain": domain,
    "is_mail_domain": is_mail,
    "is_no_mail_domain": is_no_mail,
    "calibrated_confidence": calibrated,
    "observations": {
        "DNSSEC_VALID": dnssec.get("status") == "success" and dnssec.get("ad_flag") is True,
        "DNSSEC_INHERITED": dnssec.get("chain_of_trust") == "inherited",
        "DNSSEC_ROLLOVER_READY": (
            cds_cdnskey.get("has_cds", False) or
            cds_cdnskey.get("has_cdnskey", False) or
            cds_cdnskey.get("automation") == "active"
        ),
        "NULL_MX": fr.get("has_null_mx", False),
        "SPF_HARD_FAIL": spf.get("all_mechanism") == "-all",
        "DMARC_REJECT": dmarc.get("policy") == "reject",
        "NO_MAIL_DOMAIN": is_no_mail,
        "MAIL_DOMAIN": is_mail,
        "TLS_RPT": tlsrpt.get("status") == "success",
        "MTA_STS_DNS": mta_sts.get("status") in ("success", "warning"),
        "CAA_PRESENT": caa.get("status") == "success" and bool(caa.get("records")),
        "DKIM_FOUND": dkim.get("status") in ("success", "warning") and dkim.get("primary_has_dkim", False),
        "DANE_PRESENT": dane.get("has_dane", False),
        "BIMI_VALID": bimi.get("status") == "success" and bimi.get("logo_valid", False),
        "SECURITY_TXT_FOUND": security_txt.get("found", False) and not security_txt.get("expired", True),
        "NO_DANGLING_DNS": dangling.get("status") == "success" and dangling.get("dangling_count", 1) == 0,
        "DELEGATION_OK": delegation.get("status") == "success",
        "NO_SECRETS_EXPOSED": secret_exp.get("status") == "clear" and secret_exp.get("finding_count", 1) == 0,
        "HTTPS_SVCB_PRESENT": https_svcb.get("has_https", False) or https_svcb.get("has_svcb", False)
    }
}

with open(DEST, "w") as f:
    json.dump(normalized, f, indent=2)

print(json.dumps(normalized, indent=2))
